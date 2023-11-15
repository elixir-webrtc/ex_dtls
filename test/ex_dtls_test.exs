defmodule ExDTLSTest do
  use ExUnit.Case, async: true

  test "start with custom cert" do
    dtls = ExDTLS.init(client_mode: false, dtls_srtp: false)

    pkey = ExDTLS.get_pkey(dtls)
    cert = ExDTLS.get_cert(dtls)

    assert dtls2 = ExDTLS.init(client_mode: false, dtls_srtp: false, pkey: pkey, cert: cert)

    assert dtls3 = ExDTLS.init(client_mode: false, dtls_srtp: false, pkey: pkey, cert: cert)

    assert ExDTLS.get_pkey(dtls2) == ExDTLS.get_pkey(dtls3)
    assert ExDTLS.get_pkey(dtls2) == ExDTLS.get_pkey(dtls3)
  end

  test "cert fingerprint" do
    dtls = ExDTLS.init(client_mode: false, dtls_srtp: false)
    fingerprint = ExDTLS.get_cert_fingerprint(dtls)
    assert byte_size(fingerprint) == 32
  end

  test "get pkey" do
    dtls = ExDTLS.init(client_mode: false, dtls_srtp: false)
    assert _pkey = ExDTLS.get_pkey(dtls)
  end

  test "get cert" do
    dtls = ExDTLS.init(client_mode: false, dtls_srtp: false)
    assert _cert = ExDTLS.get_cert(dtls)
  end

  test "generate cert" do
    assert cert = ExDTLS.generate_cert()
    assert cert != <<>>
    assert is_binary(cert) == true
  end
end
