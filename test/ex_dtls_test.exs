defmodule ExDTLSTest do
  use ExUnit.Case, async: false

  for impl <- [:nif, :cnode] do
    @implementation impl
    describe "#{@implementation}" do
      setup do
        Application.put_env(:ex_dtls, :impl, @implementation)
      end

      test "start with custom cert" do
        {:ok, pid} = ExDTLS.start_link(client_mode: false, dtls_srtp: false)

        {:ok, pkey} = ExDTLS.get_pkey(pid)
        {:ok, cert} = ExDTLS.get_cert(pid)

        assert {:ok, pid2} =
                 ExDTLS.start_link(client_mode: false, dtls_srtp: false, pkey: pkey, cert: cert)

        assert {:ok, pid3} =
                 ExDTLS.start_link(client_mode: false, dtls_srtp: false, pkey: pkey, cert: cert)

        assert ExDTLS.get_pkey(pid2) == ExDTLS.get_pkey(pid3)
        assert ExDTLS.get_cert(pid2) == ExDTLS.get_cert(pid3)
      end

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

      test "stop" do
        {:ok, pid} = ExDTLS.start_link(client_mode: false, dtls_srtp: false)
        assert :ok = ExDTLS.stop(pid)
      end
    end
  end

  test "Invalid impl" do
    Application.put_env(:ex_dtls, :impl, :invalid)

    assert {:error, {%ArgumentError{}, _stacktrace}} =
             ExDTLS.start(impl: :invalid, client_mode: false, dtls_srtp: false)
  end
end
