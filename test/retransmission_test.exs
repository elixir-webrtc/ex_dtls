defmodule ExDTLS.RetransmissionTest do
  use ExUnit.Case, async: true

  test "check retransmission" do
    {:ok, rx_pid} = ExDTLS.start_link(client_mode: false, dtls_srtp: true)
    {:ok, tx_pid} = ExDTLS.start_link(client_mode: true, dtls_srtp: true)

    ExDTLS.do_handshake(tx_pid)
    packets = wait_for_retransmission(tx_pid)

    ExDTLS.process(rx_pid, packets)
    packets = wait_for_retransmission(rx_pid)

    ExDTLS.process(tx_pid, packets)
    packets = wait_for_retransmission(tx_pid)

    assert finish_hsk(rx_pid, tx_pid, packets) == :ok
  end

  defp wait_for_retransmission(pid, first? \\ true) do
    receive do
      1000 ->
        wait_for_retransmission(pid, false)

      {:ex_dtls, ^pid, {:retransmit, packets}} ->
        packets

      _other ->
        wait_for_retransmission(pid, first?)
    end
  end

  defp finish_hsk(pid1, pid2, packets) do
    {:handshake_finished, _handshake_data, packets} = ExDTLS.process(pid1, packets)

    {:handshake_finished, _handshake_data} = ExDTLS.process(pid2, packets)

    :ok
  end

  @tag :long_running
  @tag timeout: :infinity
  test "check reaching timeout limit" do
    Process.flag(:trap_exit, true)

    {:ok, rx_pid} = ExDTLS.start(client_mode: false, dtls_srtp: true)
    {:ok, tx_pid} = ExDTLS.start(client_mode: true, dtls_srtp: true)
    {:ok, packets} = ExDTLS.do_handshake(tx_pid)
    {:handshake_packets, _packets} = ExDTLS.process(rx_pid, packets)

    tx_monitor = Process.monitor(tx_pid)
    rx_monitor = Process.monitor(rx_pid)

    # ignore retransmissions
    Process.sleep(ExDTLS.get_max_retransmit_timeout() * 2_000)

    assert_received(
      {:DOWN, ^tx_monitor, :process, ^tx_pid,
       {%RuntimeError{message: "DTLS handshake reached max retransmission number"}, _}},
      2000
    )

    assert_received(
      {:DOWN, ^rx_monitor, :process, ^rx_pid,
       {%RuntimeError{message: "DTLS handshake reached max retransmission number"}, _}},
      2000
    )
  end
end
