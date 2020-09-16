defmodule DTLS do
  require Unifex.CNode

  def init(socket_path) do
    {:ok, pid} = Unifex.CNode.start_link(:native)
    Unifex.CNode.call(pid, :init, [socket_path])
  end

  def do_handshake() do
    Unifex.CNode.call(pid, :do_handshake)
    receive do
      msg ->
        IO.inspect(msg)
        msg
    after 5000 ->
      {:timeout}
    end
  end

end
