defmodule ExDTLS.HaltTest do
  # not async: every VM started here saturates all dirty CPU schedulers
  use ExUnit.Case, async: false

  @vms 8
  @max_concurrency 4

  # The VM keeps running dirty NIFs while it exits, so a key generation can
  # still be in flight when `exit()` runs OpenSSL's atexit cleanup.
  # `:crypto` initializes OpenSSL first, as in apps that use both.
  @halt_during_key_generation """
  :crypto.strong_rand_bytes(1)

  for _worker <- 1..System.schedulers_online() do
    spawn(fn -> Stream.repeatedly(&ExDTLS.generate_key_cert/0) |> Stream.run() end)
  end

  Process.sleep(Enum.random(100..400))
  System.halt(0)
  """

  @tag timeout: 120_000
  test "VM halts cleanly while keys are being generated" do
    code_path = Enum.flat_map(:code.get_path(), &["-pa", to_string(&1)])

    exit_statuses =
      1..@vms
      |> Task.async_stream(
        fn _vm ->
          {_output, status} =
            System.cmd("elixir", code_path ++ ["-e", @halt_during_key_generation],
              stderr_to_stdout: true
            )

          status
        end,
        max_concurrency: @max_concurrency,
        timeout: :infinity
      )
      |> Enum.map(fn {:ok, status} -> status end)

    assert Enum.all?(exit_statuses, &(&1 == 0)),
           "VM exit statuses: #{inspect(Enum.frequencies(exit_statuses))}"
  end
end
