defmodule ExDTLS.SchedulerTest do
  # not async: the test saturates all schedulers on purpose
  use ExUnit.Case, async: false

  @duration_ms 1_500
  @max_latency_ms 50

  setup_all do
    # the first call loads the NIF library, which stalls the VM on its own
    ExDTLS.generate_key_cert()
    :ok
  end

  setup do
    # Saturating all schedulers would also saturate all CPU cores, and then the OS,
    # not the VM, starves the measuring process. Limit both normal and dirty CPU
    # schedulers (the latter scale proportionally) to leave free cores.
    previous = :erlang.system_flag(:schedulers_online, 1)
    on_exit(fn -> :erlang.system_flag(:schedulers_online, previous) end)
  end

  test "key generation does not block normal schedulers" do
    started = System.monotonic_time(:millisecond)
    deadline = started + @duration_ms

    workers =
      for _worker <- 1..System.schedulers_online() do
        Task.async(fn -> generate_until(deadline) end)
      end

    max_latency = measure_max_latency(started, deadline, 0)
    Task.await_many(workers, @duration_ms * 2)

    assert max_latency < @max_latency_ms,
           "process waited #{max_latency} ms for a scheduler while keys were being generated"
  end

  defp generate_until(deadline) do
    if System.monotonic_time(:millisecond) < deadline do
      ExDTLS.generate_key_cert()
      ExDTLS.init(mode: :server, dtls_srtp: false)
      generate_until(deadline)
    end
  end

  # The first gap is measured from before the workers were spawned, so a stall
  # that lasts until the deadline is still counted.
  defp measure_max_latency(last, deadline, max_latency) do
    Process.sleep(1)
    now = System.monotonic_time(:millisecond)
    max_latency = max(now - last - 1, max_latency)

    if now < deadline do
      measure_max_latency(now, deadline, max_latency)
    else
      max_latency
    end
  end
end
