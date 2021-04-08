defmodule ExDTLSTest do
  use ExUnit.Case, async: true

  test "cert fingerprint" do
    {:ok, pid} = ExDTLS.start_link(client_mode: false, dtls_srtp: false)
    {:ok, fingerprint} = ExDTLS.get_cert_fingerprint(pid)
    assert byte_size(fingerprint) == 32
  end

  test "get pkey" do
    {:ok, pid} = ExDTLS.start_link(client_mode: false, dtls_srtp: false)
    assert {:ok, _pkey} = ExDTLS.get_pkey(pid)
  end

  test "get cert" do
    {:ok, pid} = ExDTLS.start_link(client_mode: false, dtls_srtp: false)
    assert {:ok, _cert} = ExDTLS.get_cert(pid)
  end

  test "generate cert" do
    {:ok, pid} = ExDTLS.start_link(client_mode: false, dtls_srtp: false)
    assert {:ok, _cert} = ExDTLS.generate_cert(pid)
  end
end
