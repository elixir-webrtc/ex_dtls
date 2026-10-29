defmodule ExDTLS.HaltTest do
  # not async: every VM started here saturates all dirty CPU schedulers
  use ExUnit.Case, async: false

  @vms 8
  @max_concurrency 4
  # keeps thread count low on many-core hosts; the workers still saturate
  # all dirty CPU schedulers, which match the normal ones in number
  @schedulers 4

  # The VM keeps running dirty NIFs while it exits, so a key generation can
  # still be in flight when `exit()` runs OpenSSL's atexit cleanup.
  # `:crypto` initializes OpenSSL first, as in apps that use both.
  @halt_during_key_generation """
  :crypto.strong_rand_bytes(1)

  for _worker <- 1..System.schedulers_online() do
    # linked, so a failed key generation fails the VM's exit status
    spawn_link(fn -> Stream.repeatedly(&ExDTLS.generate_key_cert/0) |> Stream.run() end)
  end

  Process.sleep(Enum.random(100..400))
  System.halt(0)
  """

  @tag timeout: 120_000
  test "VM halts cleanly while keys are being generated" do
    # "." would make the child resolve `:ex_dtls` to the project root, which
    # has no compiled NIF, when the project directory is named `ex_dtls`
    code_path =
      :code.get_path()
      |> Enum.reject(&(&1 == ~c"."))
      |> Enum.flat_map(&["-pa", to_string(&1)])

    erl_flags = ["--erl", "+S #{@schedulers}"]

    exit_statuses =
      1..@vms
      |> Task.async_stream(
        fn _vm ->
          {_output, status} =
            System.cmd("elixir", erl_flags ++ code_path ++ ["-e", @halt_during_key_generation],
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
