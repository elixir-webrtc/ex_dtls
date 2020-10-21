defmodule ExDTLSTest do
  use ExUnit.Case, async: true

  test "dtls-srtp" do
    {:ok, rx_pid} = ExDTLS.start_link(client_mode: false, dtls_srtp: true)
    {:ok, tx_pid} = ExDTLS.start_link(client_mode: true, dtls_srtp: true)
    {:ok, packets} = ExDTLS.do_handshake(tx_pid)
    assert :ok == loop({rx_pid, false}, {tx_pid, false}, packets)
  end

  defp loop({_pid1, true}, {_pid2, true}, _packets) do
    :ok
  end

  defp loop({pid1, false}, {pid2, true}, packets) do
    {:finished, _keying_material} = ExDTLS.do_handshake(pid1, packets)
    loop({pid2, true}, {pid1, true}, nil)
  end

  defp loop({pid1, state1}, {pid2, state2}, packets) do
    case ExDTLS.do_handshake(pid1, packets) do
      {:ok, packets} ->
        loop({pid2, state2}, {pid1, state1}, packets)

      {:finished_with_packets, _handshake_data, packets} ->
        loop({pid2, state2}, {pid1, true}, packets)
    end
  end
end
