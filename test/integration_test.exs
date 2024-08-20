defmodule ExDTLS.IntegrationTest do
  use ExUnit.Case, async: true

  test "dtls_srtp" do
    rx_dtls = ExDTLS.init(mode: :server, dtls_srtp: true, verify_peer: true)
    tx_dtls = ExDTLS.init(mode: :client, dtls_srtp: true, verify_peer: true)

    {packets, _timeout} = ExDTLS.do_handshake(tx_dtls)

    assert :ok == loop({rx_dtls, false}, {tx_dtls, false}, packets)

    assert ExDTLS.get_peer_cert(tx_dtls) == ExDTLS.get_cert(rx_dtls)
    assert ExDTLS.get_peer_cert(rx_dtls) == ExDTLS.get_cert(tx_dtls)
  end

  test "dtls_srtp with no verify_peer" do
    rx_dtls = ExDTLS.init(mode: :server, dtls_srtp: true)
    tx_dtls = ExDTLS.init(mode: :client, dtls_srtp: true)

    {packets, _timeout} = ExDTLS.do_handshake(tx_dtls)

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

    {packets, _timeout} = ExDTLS.do_handshake(cl_dtls)
    assert :ok == loop({sr_dtls, false}, {cl_dtls, false}, packets)

    msg = <<1, 3, 2, 5>>
    assert {:ok, data} = ExDTLS.write_data(cl_dtls, msg)
    assert data != msg
    assert {:ok, ^msg} = ExDTLS.handle_data(sr_dtls, data)

    msg = <<1, 3, 8, 9>>
    assert {:ok, data} = ExDTLS.write_data(sr_dtls, msg)
    assert data != msg
    assert {:ok, ^msg} = ExDTLS.handle_data(cl_dtls, data)
  end

  test "expired cert" do
    # generate expired cert
    {key, cert} = ExDTLS.generate_key_cert(-1, 0)

    rx_dtls =
      ExDTLS.init(mode: :server, dtls_srtp: true, verify_peer: true, pkey: key, cert: cert)

    tx_dtls = ExDTLS.init(mode: :client, dtls_srtp: true, verify_peer: true)

    {packets, _timeout} = ExDTLS.do_handshake(tx_dtls)
    {:handshake_packets, packets, _timeout} = ExDTLS.handle_data(rx_dtls, packets)
    assert {:error, :handshake_error} = ExDTLS.handle_data(tx_dtls, packets)
  end

  defp loop({_dtls1, true}, {_dtls2, true}, _packets) do
    :ok
  end

  defp loop({dtls1, state1}, {dtls2, state2}, packets) do
    case ExDTLS.handle_data(dtls1, packets) do
      {:handshake_packets, packets, _timeout} ->
        loop({dtls2, state2}, {dtls1, state1}, packets)

      {:handshake_finished, _lkm, _rkm, _p, packets} ->
        loop({dtls2, state2}, {dtls1, true}, packets)

      {:handshake_finished, _lkm, _rkm, _p} ->
        loop({dtls2, state2}, {dtls1, true}, packets)
    end
  end
end
