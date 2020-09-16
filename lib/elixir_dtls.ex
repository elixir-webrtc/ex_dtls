defmodule ElixirDTLS do
  use Agent

  require Unifex.CNode

  defmodule State do
    defstruct cnode: nil,
              pid: nil
  end

  def start_link(out_socket_path, client_mode) do
    {:ok, pid} = Agent.start_link(fn -> init(out_socket_path, client_mode) end)
    pid
  end

  defp init(socket_path, client_mode) do
    {:ok, pid} = Unifex.CNode.start_link(:native)
    Unifex.CNode.call(pid, :init, [socket_path, client_mode])
    %State{cnode: pid}
  end

  def do_handshake(pid) do
    %State{cnode: cnode} = Agent.get(pid, fn state -> state end)
    Unifex.CNode.call(cnode, :do_handshake)

    receive do
      msg ->
        IO.inspect(msg, label: "dtls agent")
        msg
    after
      5000 -> {:timeout}
    end
  end

  def accept_handshake(pid) do
    receive do
      msg ->
        IO.inspect(msg, label: "dtls agent")
        msg
    after
      5000 -> {:timeout}
    end
  end
end
