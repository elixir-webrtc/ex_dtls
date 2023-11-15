defmodule ExDTLS.RetransmissionTest do
  use ExUnit.Case, async: true

  test "retransmission" do
    rx_dtls = ExDTLS.init(client_mode: false, dtls_srtp: true)
    tx_dtls = ExDTLS.init(client_mode: true, dtls_srtp: true)

    {_packets, timeout} = ExDTLS.do_handshake(tx_dtls)
    Process.send_after(self(), {:handle_timeout, :tx}, timeout)
    {:retransmit, packets, timeout} = wait_for_timeout(tx_dtls, :tx)
    Process.send_after(self(), {:handle_timeout, :tx}, timeout)

    {:handshake_packets, _packets, timeout} = ExDTLS.process(rx_dtls, packets)
    Process.send_after(self(), {:handle_timeout, :rx}, timeout)
    {:retransmit, packets, _timeout} = wait_for_timeout(rx_dtls, :rx)

    # Create some space between the old timeout and the upcoming one.
    # In other case those two timeouts can be very close to each other
    # and waiting for the old one and handling it can trigger retransmission
    # instead of noop
    Process.sleep(500)
    {:handshake_packets, _packets, timeout} = ExDTLS.process(tx_dtls, packets)
    Process.send_after(self(), {:handle_timeout, :tx}, timeout)
    # wait for the old timeout
    :ok = wait_for_timeout(tx_dtls, :tx)
    # wait for the latest timeout
    {:retransmit, packets, _timeout} = wait_for_timeout(tx_dtls, :tx)

    assert finish_hsk(rx_dtls, tx_dtls, packets) == :ok
  end

  defp wait_for_timeout(dtls, dtls_type) do
    receive do
      {:handle_timeout, ^dtls_type} -> ExDTLS.handle_timeout(dtls)
    end
  end

  defp finish_hsk(rx_dtls, tx_dtls, packets) do
    {:handshake_finished, _lkm, _rkm, _p, packets} = ExDTLS.process(rx_dtls, packets)
    {:handshake_finished, _lkm, _rkm, _p} = ExDTLS.process(tx_dtls, packets)
    :ok
  end
end
