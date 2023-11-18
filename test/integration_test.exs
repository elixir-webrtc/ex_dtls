defmodule ExDTLS.IntegrationTest do
  use ExUnit.Case, async: true

  test "dtls_srtp" do
    rx_dtls = ExDTLS.init(client_mode: false, dtls_srtp: true)
    tx_dtls = ExDTLS.init(client_mode: true, dtls_srtp: true)

    {packets, _timeout} = ExDTLS.do_handshake(tx_dtls)

    assert :ok == loop({rx_dtls, false}, {tx_dtls, false}, packets)

    assert ExDTLS.get_peer_cert(tx_dtls) == ExDTLS.get_cert(rx_dtls)
    assert ExDTLS.get_peer_cert(rx_dtls) == ExDTLS.get_cert(tx_dtls)
  end

  test "dtls_srtp with no verify_peer" do
    rx_dtls = ExDTLS.init(client_mode: false, dtls_srtp: true, verify_peer: false)
    tx_dtls = ExDTLS.init(client_mode: true, dtls_srtp: true)

    {packets, _timeout} = ExDTLS.do_handshake(tx_dtls)

    assert :ok == loop({rx_dtls, false}, {tx_dtls, false}, packets)

    assert ExDTLS.get_peer_cert(tx_dtls) == ExDTLS.get_cert(rx_dtls)
    # Client only sends its certificate when requested to do so by the server.
    # Because `verify_peer` is set to `false`, server won't ask for the client's certificate. 
    assert ExDTLS.get_peer_cert(rx_dtls) == nil
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
