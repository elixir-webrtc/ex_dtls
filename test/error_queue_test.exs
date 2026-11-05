defmodule ExDTLS.ErrorQueueTest do
  # not async: with one scheduler, all NIF calls share one OpenSSL error queue
  use ExUnit.Case, async: false

  setup do
    previous = :erlang.system_flag(:schedulers_online, 1)
    on_exit(fn -> :erlang.system_flag(:schedulers_online, previous) end)
  end

  test "close_notify is handled with a stale error in the queue" do
    rx_dtls = ExDTLS.init(mode: :server, dtls_srtp: true)
    tx_dtls = ExDTLS.init(mode: :client, dtls_srtp: true)
    {:ok, packets, _timeout} = ExDTLS.do_handshake(tx_dtls)
    :ok = handshake(rx_dtls, tx_dtls, packets)
    {:ok, [close_notify]} = ExDTLS.close(tx_dtls)

    # SSL_shutdown during a handshake leaves an error in the queue
    dtls = ExDTLS.init(mode: :client, dtls_srtp: true)
    {:ok, _packets, _timeout} = ExDTLS.do_handshake(dtls)
    assert {:ok, []} = ExDTLS.close(dtls)

    assert {:error, :peer_closed_for_writing} = ExDTLS.handle_data(rx_dtls, close_notify)
  end

  defp handshake(_to, _from, []), do: :ok

  defp handshake(to, from, packets) do
    packets
    |> Enum.flat_map(fn packet ->
      case ExDTLS.handle_data(to, packet) do
        {:handshake_packets, packets, _timeout} -> packets
        {:handshake_finished, _lkm, _rkm, _profile, packets} -> packets
        {:handshake_finished, _lkm, _rkm, _profile} -> []
        :handshake_want_read -> []
      end
    end)
    |> then(&handshake(from, to, &1))
  end
end
