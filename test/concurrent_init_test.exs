defmodule ExDTLS.ConcurrentInitTest do
  use ExUnit.Case, async: false

  @moduletag timeout: 300_000

  test "many DTLS contexts can be created and driven concurrently" do
    {pkey, cert} = ExDTLS.generate_key_cert()

    results =
      1..50_000
      |> Task.async_stream(
        fn i ->
          mode = if rem(i, 2) == 0, do: :client, else: :server
          dtls = ExDTLS.init(mode: mode, dtls_srtp: true, pkey: pkey, cert: cert)

          if mode == :client do
            {:ok, _packets, _timeout} = ExDTLS.do_handshake(dtls)
          end

          :ok
        end,
        max_concurrency: System.schedulers_online() * 8,
        ordered: false,
        timeout: 300_000
      )
      |> Enum.map(fn {:ok, res} -> res end)

    assert Enum.all?(results, &(&1 == :ok))
  end
end
