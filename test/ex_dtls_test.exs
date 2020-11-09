defmodule ExDTLSTest do
  use ExUnit.Case, async: true

  test "cert fingerprint" do
    {:ok, pid} = ExDTLS.start_link(client_mode: false, dtls_srtp: false)
    {:ok, fingerprint} = ExDTLS.get_cert_fingerprint(pid)
    assert byte_size(fingerprint) == 32
  end
end
