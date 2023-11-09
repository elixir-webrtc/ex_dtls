defmodule ExDTLSTest do
  use ExUnit.Case, async: true

  test "start with custom cert" do
    dtls = ExDTLS.init(client_mode: false, dtls_srtp: false)

    {pkey, dtls} = ExDTLS.get_pkey(dtls)
    {cert, _dtls} = ExDTLS.get_cert(dtls)

    assert dtls2 = ExDTLS.init(client_mode: false, dtls_srtp: false, pkey: pkey, cert: cert)

    assert dtls3 = ExDTLS.init(client_mode: false, dtls_srtp: false, pkey: pkey, cert: cert)

    {dtls2_pkey, dtls2} = ExDTLS.get_pkey(dtls2)
    {dtls2_cert, _dtls2} = ExDTLS.get_pkey(dtls2)
    {dtls3_pkey, dtls3} = ExDTLS.get_pkey(dtls3)
    {dtls3_cert, _dtls3} = ExDTLS.get_pkey(dtls3)

    assert dtls2_pkey == dtls3_pkey
    assert dtls2_cert == dtls3_cert
  end

  test "cert fingerprint" do
    dtls = ExDTLS.init(client_mode: false, dtls_srtp: false)
    {fingerprint, _dtls} = ExDTLS.get_cert_fingerprint(dtls)
    assert byte_size(fingerprint) == 32
  end

  test "get pkey" do
    dtls = ExDTLS.init(client_mode: false, dtls_srtp: false)
    assert {_pkey, _dtls} = ExDTLS.get_pkey(dtls)
  end

  test "get cert" do
    dtls = ExDTLS.init(client_mode: false, dtls_srtp: false)
    assert {_cert, _dtls} = ExDTLS.get_cert(dtls)
  end

  test "generate cert" do
    dtls = ExDTLS.init(client_mode: false, dtls_srtp: false)
    assert {_cert, _dtls} = ExDTLS.generate_cert(dtls)
  end
end
