defmodule ExDTLSTest do
  use ExUnit.Case, async: true

  test "start with custom cert" do
    dtls = ExDTLS.init(mode: :server, dtls_srtp: false)

    pkey = ExDTLS.get_pkey(dtls)
    cert = ExDTLS.get_cert(dtls)

    assert dtls2 = ExDTLS.init(mode: :server, dtls_srtp: false, pkey: pkey, cert: cert)

    assert dtls3 = ExDTLS.init(mode: :server, dtls_srtp: false, pkey: pkey, cert: cert)

    assert ExDTLS.get_pkey(dtls2) == ExDTLS.get_pkey(dtls3)
    assert ExDTLS.get_pkey(dtls2) == ExDTLS.get_pkey(dtls3)
  end

  test "cert fingerprint" do
    assert {_pkey, cert} = ExDTLS.generate_key_cert()
    fingerprint = ExDTLS.get_cert_fingerprint(cert)
    assert byte_size(fingerprint) == 32
  end

  test "get pkey" do
    dtls = ExDTLS.init(mode: :server, dtls_srtp: false)
    assert _pkey = ExDTLS.get_pkey(dtls)
  end

  test "get cert" do
    dtls = ExDTLS.init(mode: :server, dtls_srtp: false)
    assert _cert = ExDTLS.get_cert(dtls)
  end

  test "generate cert" do
    assert {pkey, cert} = ExDTLS.generate_key_cert()
    assert pkey != <<>>
    assert cert != <<>>
    assert is_binary(pkey) == true
    assert is_binary(cert) == true
  end

  test "get peer cert" do
    dtls = ExDTLS.init(mode: :server, dtls_srtp: false)
    # before finishing handshake, there should be no peer cert
    assert nil == ExDTLS.get_peer_cert(dtls)
  end
end
