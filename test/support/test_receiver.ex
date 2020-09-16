defmodule ElixirDTLS.Support.TestReceiver do
  use Agent

  alias ElixirDTLS

  defmodule State do
    defstruct listen_socket: nil,
              peer_socket: nil,
              dtls_socket: nil,
              dtls_pid: nil,
              dtls_to_peer_pid: nil,
              peer_to_dtls_pid: nil
  end

  def start_link(port) do
    Agent.start_link(fn -> init_socket(port) end, name: __MODULE__)
  end

  defp init_socket(port) do
    {:ok, listen_socket} = :socket.open(:inet, :stream, :tcp)
    addr = %{:family => :inet, :port => port, :addr => {127, 0, 0, 1}}
    {:ok, _port} = :socket.bind(listen_socket, addr)
    :ok = :socket.listen(listen_socket)
    %State{listen_socket: listen_socket}
  end

  def accept() do
    %State{listen_socket: listen_socket} = Agent.get(__MODULE__, fn state -> state end)
    {:ok, socket} = :socket.accept(listen_socket)
    Agent.update(__MODULE__, fn state -> %State{state | peer_socket: socket} end)
  end

  def init_dtls_module(dtls_socket_path) do
    dtls_pid = ElixirDTLS.start_link(dtls_socket_path, false)
    {:ok, socket} = :socket.open(:local, :stream, :default)
    addr = %{:family => :local, :path => dtls_socket_path}
    :ok = :socket.connect(socket, addr)

    Agent.update(__MODULE__, fn state ->
      %State{state | dtls_socket: socket, dtls_pid: dtls_pid}
    end)
  end

  def run_transmit_process() do
    %State{peer_socket: peer_socket, dtls_socket: dtls_socket} =
      Agent.get(__MODULE__, fn state -> state end)

    dtls_to_peer_pid =
      spawn(fn ->
        dtls_to_peer(dtls_socket, peer_socket)
      end)

    peer_to_dtls_pid =
      spawn(fn ->
        peer_to_dtls(dtls_socket, peer_socket)
      end)

    :ok =
      Agent.update(__MODULE__, fn state ->
        %State{state | dtls_to_peer_pid: dtls_to_peer_pid, peer_to_dtls_pid: peer_to_dtls_pid}
      end)
  end

  defp dtls_to_peer(dtls_socket, peer_socket) do
    {:ok, data} = :socket.recv(dtls_socket)
    :socket.send(peer_socket, data)
    dtls_to_peer(dtls_socket, peer_socket)
  end

  defp peer_to_dtls(dtls_socket, peer_socket) do
    {:ok, data} = :socket.recv(peer_socket)
    :socket.send(dtls_socket, data)
    peer_to_dtls(dtls_socket, peer_socket)
  end

  def accept_handshake() do
    %State{
      dtls_pid: dtls_pid,
      dtls_to_peer_pid: dtls_to_peer_pid,
      peer_to_dtls_pid: peer_to_dtls_pid
    } = Agent.get(__MODULE__, fn state -> state end)

    res = ElixirDTLS.accept_handshake(dtls_pid)
    Process.exit(dtls_to_peer_pid, :normal)
    Process.exit(peer_to_dtls_pid, :normal)
    destroy()
    res
  end

  def destroy() do
    %State{
      listen_socket: listen_socket,
      peer_socket: peer_socket,
      dtls_socket: dtls_socket
    } = Agent.get(__MODULE__, fn state -> state end)

    :socket.shutdown(listen_socket, :read_write)
    :socket.shutdown(peer_socket, :read_write)
    :socket.shutdown(dtls_socket, :read_write)
    :socket.close(listen_socket)
    :socket.close(peer_socket)
    :socket.close(dtls_socket)
  end
end
