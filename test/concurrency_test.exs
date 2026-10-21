defmodule ExDTLS.ConcurrencyTest do
  use ExUnit.Case, async: false

  @inits_per_process 200

  test "DTLS contexts created concurrently can start a handshake" do
    {pkey, cert} = ExDTLS.generate_key_cert()

    1..(System.schedulers_online() * 4)
    |> Task.async_stream(
      fn _i ->
        for _j <- 1..@inits_per_process do
          dtls = ExDTLS.init(mode: :client, dtls_srtp: true, pkey: pkey, cert: cert)
          assert {:ok, [_packet | _packets], _timeout} = ExDTLS.do_handshake(dtls)
        end
      end,
      max_concurrency: System.schedulers_online() * 4,
      timeout: :infinity
    )
    |> Enum.each(fn result -> assert {:ok, _result} = result end)
  end
end
