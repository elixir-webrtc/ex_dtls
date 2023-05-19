defmodule ExDTLS.IntegrationTest do
  use ExUnit.Case, async: false

  setup ctx do
    Application.put_env(:ex_dtls, :impl, ctx[:impl])
  end

  @tag impl: :nif
  test "NIF dtls_srtp" do
    run_test()
  end

  @tag impl: :cnode
  test "CNode dtls_srtp" do
    run_test()
  end

  defp run_test() do
    {:ok, rx_pid} = ExDTLS.start_link(client_mode: false, dtls_srtp: true)
    {:ok, tx_pid} = ExDTLS.start_link(client_mode: true, dtls_srtp: true)
    {:ok, packets} = ExDTLS.do_handshake(tx_pid)
    assert :ok == loop({rx_pid, false}, {tx_pid, false}, packets)
  end

  defp loop({_pid1, true}, {_pid2, true}, _packets) do
    :ok
  end

  defp loop({pid1, false}, {pid2, true}, packets) do
    {:handshake_finished, _handshake_data} = ExDTLS.process(pid1, packets)
    loop({pid2, true}, {pid1, true}, nil)
  end

  defp loop({pid1, state1}, {pid2, state2}, packets) do
    case ExDTLS.process(pid1, packets) do
      {:handshake_packets, packets} ->
        loop({pid2, state2}, {pid1, state1}, packets)

      {:handshake_finished, _handshake_data, packets} ->
        loop({pid2, state2}, {pid1, true}, packets)
    end
  end
end
