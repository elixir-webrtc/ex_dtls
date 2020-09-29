defmodule ExDTLSTest do
  use ExUnit.Case, async: true

  alias ExDTLS.Support.TestPeer

  test "dtls-srtp" do
    port = 40_070
    {:ok, rx_pid} = TestPeer.start_link(self(), false)
    {:ok, tx_pid} = TestPeer.start_link(self(), true)

    :ok = TestPeer.listen(rx_pid, port)
    :ok = TestPeer.connect(tx_pid, port)
    :ok = TestPeer.accept(rx_pid)

    :ok = TestPeer.run_transmit_process(rx_pid)
    :ok = TestPeer.run_transmit_process(tx_pid)

    :ok = TestPeer.do_handshake(tx_pid)

    assert_receive({:handshake_finished, keying_material}, 3000)
    assert_receive({:handshake_finished, keying_material}, 3000)
  end
end
