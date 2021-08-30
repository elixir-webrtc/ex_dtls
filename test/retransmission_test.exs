defmodule ExDTLS.RetransmissionTest do
  use ExUnit.Case, async: true

  test "check retransmission" do
    {:ok, rx_pid} = ExDTLS.start_link(client_mode: false, dtls_srtp: true)
    {:ok, tx_pid} = ExDTLS.start_link(client_mode: true, dtls_srtp: true)
    {:ok, packets} = ExDTLS.do_handshake(tx_pid)
    assert :ok == loop({rx_pid, false}, {tx_pid, false}, packets)
  end

  defp loop({pid1, false}, {pid2, state2}, packets) do
    case process_second_message(pid1, packets) do
      {:retransmit, _component, packets} -> loop({pid2, state2}, {pid1, true}, packets)
      :error -> :error
    end
  end

  defp loop({pid1, true}, {pid2, true}, packets) do
    {:handshake_finished, _handshake_data, packets} = ExDTLS.process(pid1, packets)
    {:handshake_finished, _handshake_data} = ExDTLS.process(pid2, packets)
    :ok
  end

  defp process_second_message(pid, packets) do
    case ExDTLS.process(pid, packets) do
      _msg -> nil
    end

    receive do
      1_000 ->
        :error

      msg ->
        msg
    end
  end
end
