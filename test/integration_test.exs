defmodule ExDTLS.IntegrationTest do
  use ExUnit.Case, async: true

  test "dtls_srtp" do
    rx_dtls = ExDTLS.init(mode: :server, dtls_srtp: true, verify_peer: true)
    tx_dtls = ExDTLS.init(mode: :client, dtls_srtp: true, verify_peer: true)

    {:ok, packets, _timeout} = ExDTLS.do_handshake(tx_dtls)

    assert :ok == loop({rx_dtls, false}, {tx_dtls, false}, packets)

    assert ExDTLS.get_peer_cert(tx_dtls) == ExDTLS.get_cert(rx_dtls)
    assert ExDTLS.get_peer_cert(rx_dtls) == ExDTLS.get_cert(tx_dtls)
  end

  test "dtls_srtp with no verify_peer" do
    rx_dtls = ExDTLS.init(mode: :server, dtls_srtp: true)
    tx_dtls = ExDTLS.init(mode: :client, dtls_srtp: true)

    {:ok, packets, _timeout} = ExDTLS.do_handshake(tx_dtls)

    assert :ok == loop({rx_dtls, false}, {tx_dtls, false}, packets)

    assert ExDTLS.get_peer_cert(tx_dtls) == ExDTLS.get_cert(rx_dtls)
    # Client only sends its certificate when requested to do so by the server.
    # Because `verify_peer` is set to `false`, server won't ask for the client's certificate.
    assert ExDTLS.get_peer_cert(rx_dtls) == nil
  end

  test "sending over DTLS" do
    sr_dtls = ExDTLS.init(mode: :server, dtls_srtp: true, verify_peer: true)
    cl_dtls = ExDTLS.init(mode: :client, dtls_srtp: true, verify_peer: true)

    assert {:error, :handshake_not_finished} = ExDTLS.write_data(sr_dtls, <<1, 2, 3>>)
    assert {:error, :handshake_not_finished} = ExDTLS.write_data(cl_dtls, <<1, 2, 3>>)

    {:ok, packets, _timeout} = ExDTLS.do_handshake(cl_dtls)
    assert :ok == loop({sr_dtls, false}, {cl_dtls, false}, packets)

    msg = <<1, 3, 2, 5>>
    assert {:ok, packets} = ExDTLS.write_data(cl_dtls, msg)
    assert {:ok, ^msg} = feed_packets(sr_dtls, packets)

    msg = <<1, 3, 8, 9>>
    assert {:ok, packets} = ExDTLS.write_data(sr_dtls, msg)
    assert {:ok, ^msg} = feed_packets(cl_dtls, packets)
  end

  test "expired cert" do
    # generate expired cert
    {key, cert} = ExDTLS.generate_key_cert(-1, 0)

    rx_dtls =
      ExDTLS.init(mode: :server, dtls_srtp: true, verify_peer: true, pkey: key, cert: cert)

    tx_dtls = ExDTLS.init(mode: :client, dtls_srtp: true, verify_peer: true)

    {:ok, packets, _timeout} = ExDTLS.do_handshake(tx_dtls)
    {:handshake_packets, packets, _timeout} = feed_packets(rx_dtls, packets)
    assert {:error, :handshake_error} = feed_packets(tx_dtls, packets)
  end

  describe "close/1" do
    test "before handshake has finished (client mode)" do
      dtls = ExDTLS.init(mode: :client, dtls_srtp: true, verify_peer: true)
      assert {:ok, []} = ExDTLS.close(dtls)
      # assert that handshake can't be started
      assert {:error, :closed} = ExDTLS.do_handshake(dtls)
    end

    test "before handshake has finished (server mode)" do
      dtls = ExDTLS.init(mode: :server, dtls_srtp: true, verify_peer: true)
      assert {:ok, []} = ExDTLS.close(dtls)
      # assert that handshake can't be started
      assert {:error, :closed} = ExDTLS.do_handshake(dtls)
    end

    test "after handshake has finished (client mode)" do
      rx_dtls = ExDTLS.init(mode: :server, dtls_srtp: true, verify_peer: true)
      tx_dtls = ExDTLS.init(mode: :client, dtls_srtp: true, verify_peer: true)

      {:ok, packets, _timeout} = ExDTLS.do_handshake(tx_dtls)

      assert :ok == loop({rx_dtls, false}, {tx_dtls, false}, packets)
      assert {:ok, [packet]} = ExDTLS.close(tx_dtls)
      assert {:error, :peer_closed_for_writing} = ExDTLS.handle_data(rx_dtls, packet)
      assert {:error, :closed} = ExDTLS.handle_timeout(tx_dtls)
      assert {:error, :closed} = ExDTLS.handle_timeout(rx_dtls)
    end

    test "after handshake has finished (server mode)" do
      rx_dtls = ExDTLS.init(mode: :server, dtls_srtp: true, verify_peer: true)
      tx_dtls = ExDTLS.init(mode: :client, dtls_srtp: true, verify_peer: true)

      {:ok, packets, _timeout} = ExDTLS.do_handshake(tx_dtls)

      assert :ok == loop({rx_dtls, false}, {tx_dtls, false}, packets)
      assert {:ok, [packet]} = ExDTLS.close(rx_dtls)
      assert {:error, :peer_closed_for_writing} = ExDTLS.handle_data(tx_dtls, packet)
      assert {:error, :closed} = ExDTLS.handle_timeout(tx_dtls)
      assert {:error, :closed} = ExDTLS.handle_timeout(rx_dtls)
    end
  end

  defp loop({_dtls1, true}, {_dtls2, true}, _packets) do
    :ok
  end

  defp loop({dtls1, state1}, {dtls2, state2}, packets) do
    case feed_packets(dtls1, packets) do
      {:handshake_packets, packets, _timeout} ->
        loop({dtls2, state2}, {dtls1, state1}, packets)

      {:handshake_finished, _lkm, _rkm, _p, packets} ->
        loop({dtls2, state2}, {dtls1, true}, packets)

      {:handshake_finished, _lkm, _rkm, _p} ->
        loop({dtls2, state2}, {dtls1, true}, packets)
    end
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
