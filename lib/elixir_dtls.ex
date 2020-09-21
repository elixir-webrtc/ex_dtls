defmodule ElixirDTLS do
  use GenServer

  require Unifex.CNode

  defmodule State do
    defstruct cnode: nil,
              parent: nil
  end

  # Client API
  def start_link(parent, out_socket_path, client_mode) do
    GenServer.start_link(__MODULE__, {parent, out_socket_path, client_mode})
  end

  def do_handshake(pid) do
    GenServer.cast(pid, :do_handshake)
  end

  # Server APi
  @impl true
  def init({parent, out_socket_path, client_mode}) do
    state = init_socket(out_socket_path, client_mode)
    state = %State{state | parent: parent}
    {:ok, state}
  end

  defp init_socket(socket_path, client_mode) do
    {:ok, pid} = Unifex.CNode.start_link(:native)
    :ok = Unifex.CNode.call(pid, :init, [socket_path, client_mode])
    %State{cnode: pid}
  end

  @impl true
  def handle_cast(:do_handshake, %State{cnode: cnode} = state) do
    :ok = Unifex.CNode.call(cnode, :do_handshake)
    {:noreply, state}
  end

  @impl true
  def handle_info(msg, %State{parent: parent} = state) do
    send(parent, msg)
    {:noreply, state}
  end
end
