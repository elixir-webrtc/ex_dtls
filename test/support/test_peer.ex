defmodule ExDTLS.Support.TestPeer do
  @moduledoc false

  use GenServer

  alias ExDTLS

  defmodule State do
    @moduledoc false

    defstruct parent: nil,
              listen_socket: nil,
              peer_socket: nil,
              dtls: nil,
              peer_to_dtls_pid: nil
  end

  # Client API
  # credo:disable-for-next-line
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  # credo:disable-for-next-line
  def listen(pid, port) do
    GenServer.call(pid, {:listen, port})
  end

  # credo:disable-for-next-line
  def connect(pid, port) do
    GenServer.call(pid, {:connect, port})
  end

  # credo:disable-for-next-line
  def init_dtls_module(pid, dtls_socket_path) do
    GenServer.call(pid, {:init_dtls_module, dtls_socket_path})
  end

  # credo:disable-for-next-line
  def run_transmit_process(pid) do
    GenServer.call(pid, :run_transmit_process)
  end

  # credo:disable-for-next-line
  def accept(pid) do
    GenServer.call(pid, :accept)
  end

  # credo:disable-for-next-line
  def do_handshake(pid) do
    GenServer.cast(pid, :do_handshake)
  end

  # Server API
  @impl true
  def init(opts) do
    {:ok, dtls} =
      ExDTLS.start_link(parent: self(), client_mode: opts[:client_mode], dtls_srtp: true)

    state = %State{parent: opts[:parent], dtls: dtls}
    {:ok, state}
  end

  def handle_call({:listen, port}, _from, state) do
    {:ok, listen_socket} = :socket.open(:inet, :stream, :tcp)
    addr = %{:family => :inet, :port => port, :addr => {127, 0, 0, 1}}
    {:ok, _port} = :socket.bind(listen_socket, addr)
    :ok = :socket.listen(listen_socket)
    new_state = %State{state | listen_socket: listen_socket}
    {:reply, :ok, new_state}
  end

  def handle_call({:connect, port}, _from, state) do
    {:ok, socket} = :socket.open(:inet, :stream, :tcp)
    addr = %{:family => :inet, :port => port, :addr => {127, 0, 0, 1}}
    :ok = :socket.connect(socket, addr)
    new_state = %State{state | peer_socket: socket}
    {:reply, :ok, new_state}
  end

  @impl true
  def handle_call(:accept, _from, %State{listen_socket: listen_socket} = state) do
    {:ok, socket} = :socket.accept(listen_socket)
    new_state = %State{state | peer_socket: socket}
    {:reply, :ok, new_state}
  end

  @impl true
  def handle_call(
        :run_transmit_process,
        _from,
        %State{peer_socket: peer_socket, dtls: dtls} = state
      ) do
    peer_to_dtls_pid =
      spawn(fn ->
        peer_to_dtls(dtls, peer_socket)
      end)

    new_state = %State{state | peer_to_dtls_pid: peer_to_dtls_pid}

    {:reply, :ok, new_state}
  end

  @impl true
  def handle_cast(:do_handshake, %State{dtls: dtls} = state) do
    :ok = ExDTLS.do_handshake(dtls)
    {:noreply, state}
  end

  @impl true
  def handle_info({:packets, data}, %State{peer_socket: peer_socket} = state) do
    :socket.send(peer_socket, data)
    {:noreply, state}
  end

  @impl true
  def handle_info(msg, %State{parent: parent} = state) do
    send(parent, msg)
    destroy(state)
    {:noreply, state}
  end

  defp peer_to_dtls(dtls, peer_socket) do
    {:ok, data} = :socket.recv(peer_socket)
    :ok = ExDTLS.feed(dtls, data)
    peer_to_dtls(dtls, peer_socket)
  end

  defp destroy(state) do
    %State{
      listen_socket: listen_socket,
      peer_socket: peer_socket,
      dtls: dtls,
      peer_to_dtls_pid: peer_to_dtls_pid
    } = state

    Process.exit(dtls, :normal)
    Process.exit(peer_to_dtls_pid, :normal)

    :socket.shutdown(listen_socket, :read_write)
    :socket.shutdown(peer_socket, :read_write)

    :socket.close(peer_socket)
    :socket.close(peer_socket)
  end
end
