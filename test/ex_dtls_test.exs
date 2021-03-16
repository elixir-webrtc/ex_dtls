defmodule ExDTLSTest do
  use ExUnit.Case, async: true

  test "cert fingerprint" do
    {:ok, pid} = ExDTLS.start_link(client_mode: false, dtls_srtp: false)
    {:ok, fingerprint} = ExDTLS.get_cert_fingerprint(pid)
    assert byte_size(fingerprint) == 32
  end

  test "get cert" do
    {:ok, pid} = ExDTLS.start_link(client_mode: false, dtls_srtp: false)
    assert {:ok, cert} = ExDTLS.get_cert(pid)
  end

  test "generate cert" do
    {:ok, pid} = ExDTLS.start_link(client_mode: false, dtls_srtp: false)
    assert {:ok, cert} = ExDTLS.generate_cert(pid)
  end

  test "set cert" do
    {:ok, pid} = ExDTLS.start_link(client_mode: false, dtls_srtp: false)
    {:ok, cert} = ExDTLS.generate_cert(pid)
    assert :ok = ExDTLS.set_cert(pid, cert)
  end

  test "set cert raises when cert is not proper" do
    {:ok, pid} = ExDTLS.start_link(client_mode: false, dtls_srtp: false)
    assert {:error, :failed_to_decode_cert} = ExDTLS.set_cert(pid, <<0, 0, 0>>)
  end
end
