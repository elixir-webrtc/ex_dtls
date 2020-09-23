defmodule ElixirDTLSTest do
  use ExUnit.Case, async: true

  alias ElixirDTLS.Support.TestReceiver
  alias ElixirDTLS.Support.TestSender

  test "dtls-srtp" do
    port = 40070
    {:ok, rx_pid} = TestReceiver.start_link(self(), port)
    {:ok, tx_pid} = TestSender.start_link(self(), port)
    :ok = TestReceiver.accept(rx_pid)

    :ok = TestReceiver.init_dtls_module(rx_pid, "elixir_dtls_test_socket_1")
    :ok = TestSender.init_dtls_module(tx_pid, "elixir_dtls_test_socket_2")

    :ok = TestReceiver.run_transmit_process(rx_pid)
    :ok = TestSender.run_transmit_process(tx_pid)

    :ok = TestReceiver.do_handshake(rx_pid)
    :ok = TestSender.do_handshake(tx_pid)

    assert_receive({:handshake_finished, keying_material}, 3000)
    assert_receive({:handshake_finished, keying_material}, 3000)
  end
end
