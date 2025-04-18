defmodule ExDTLS.RetransmissionTest do
  use ExUnit.Case, async: true

  test "retransmission" do
    rx_dtls = ExDTLS.init(mode: :server, dtls_srtp: true)
    tx_dtls = ExDTLS.init(mode: :client, dtls_srtp: true)

    {_packets, timeout} = ExDTLS.do_handshake(tx_dtls)
    Process.send_after(self(), {:handle_timeout, :tx}, timeout)
    {:retransmit, packets, timeout} = wait_for_timeout(tx_dtls, :tx)
    Process.send_after(self(), {:handle_timeout, :tx}, timeout)

    {:handshake_packets, _packets, timeout} = feed_packets(rx_dtls, packets)
    Process.send_after(self(), {:handle_timeout, :rx}, timeout)
    {:retransmit, packets, _timeout} = wait_for_timeout(rx_dtls, :rx)

    # Create some space between the old timeout and the upcoming one.
    # In other case those two timeouts can be very close to each other
    # and waiting for the old one and handling it can trigger retransmission
    # instead of noop
    Process.sleep(500)
    {:handshake_packets, _packets, timeout} = feed_packets(tx_dtls, packets)
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
    {:handshake_finished, _lkm, _rkm, _p, packets} = feed_packets(rx_dtls, packets)
    {:handshake_finished, _lkm, _rkm, _p} = feed_packets(tx_dtls, packets)
    :ok
  end

  defp feed_packets(dtls, [packet | packets]) do
    case ExDTLS.handle_data(dtls, packet) do
      :handshake_want_read -> feed_packets(dtls, packets)
      # it seems that handshake error (e.g. when a certificate is too old)
      # may appear before consuming all packets
      {:error, :handshake_error} = msg -> msg
      other when packets == [] -> other
    end
  end
end
