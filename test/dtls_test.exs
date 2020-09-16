defmodule ElixirDTLSTest do
  use ExUnit.Case, async: true

  alias ElixirDTLS.Support.TestReceiver
  alias ElixirDTLS.Support.TestSender

  test "dtls" do
    :file.delete("socket1")
    :file.delete("socket2")

    port = 40054
    {:ok, _rx_pid} = TestReceiver.start_link(port)
    {:ok, _tx_pid} = TestSender.start_link(port)
    TestReceiver.accept()

    TestReceiver.init_dtls_module("socket1")
    TestSender.init_dtls_module("socket2")

    TestReceiver.run_transmit_process()
    TestSender.run_transmit_process()

    assert {:handshake_finished, keying_material} = TestSender.do_handshake()
    assert {:handshake_finished, keying_material} = TestReceiver.accept_handshake()

    :timer.sleep(1000)
  end
end
