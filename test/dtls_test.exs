defmodule ElixirDTLSTest do
  use ExUnit.Case, async: true

  alias ElixirDTLS.Support.TestReceiver
  alias ElixirDTLS.Support.TestSender

  test "dtls" do
    :file.delete("socket1")
    :file.delete("socket2")

    port = 40059
    {:ok, rx_pid} = TestReceiver.start_link(self(), port)
    {:ok, tx_pid} = TestSender.start_link(self(), port)
    :ok = TestReceiver.accept(rx_pid)

    :ok = TestReceiver.init_dtls_module(rx_pid, "socket1")
    :ok = TestSender.init_dtls_module(tx_pid, "socket2")

    :ok = TestReceiver.run_transmit_process(rx_pid)
    :ok = TestSender.run_transmit_process(tx_pid)

    :ok = TestSender.do_handshake(tx_pid)

    assert_receive({:handshake_finished, keying_material}, 10000)
    assert_receive({:handshake_finished, keying_material}, 10000)
  end
end
