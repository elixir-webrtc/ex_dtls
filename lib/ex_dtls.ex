defmodule ExDTLS do
  @moduledoc """
  Module that allows performing DTLS handshake including a DTLS-SRTP one.

  `ExDTLS` executes native OpenSSL functions to perform DTLS handshake.
  It doesn't create or require any socket.
  Instead, it returns generated DTLS packets, which then have to be transported to the peer.
  """

  alias ExDTLS.Native

  @typedoc """
  Type describing ExDTLS configuration.

  See `init/1` for the meaning of each option
  """
  @type opts_t :: [
          mode: :client | :server,
          dtls_srtp: boolean(),
          pkey: binary(),
          cert: binary(),
          verify_peer: boolean()
        ]

  @typedoc """
  Supported protection profiles.

  For meaning of these values please refer to
  https://www.iana.org/assignments/srtp-protection/srtp-protection.xhtml
  """
  @type protection_profile_t() :: 0x01 | 0x02 | 0x07 | 0x08

  @typedoc """
  A reference to `ExDTLS` native.
  """
  @type dtls() :: reference()

  @doc """
  Initializes `ExDTLS`.

  Accepts a keyword list with the following options (`t:opts_t/0`):
  * `mode` - `:client` if ExDTLS module should work as a client or `:server` if as a server.
    This option is required.
  * `dtls_srtp` - `true` if DTLS-SRTP handshake should be performed or `false` if a normal one.
    Defaults to `false`.
  * `pkey` - private key to use in this SSL context. Must correspond to `cert`.
    If both `pkey` and `cert` are not passed, `ExDTLS` will generate 2048-bit RSA key and certificate on its own.
  * `cert` - certificate to use in this SSL context. Must correspond to `pkey`.
    If both `pkey` and `cert` are not passed, `ExDTLS` will generate 2048-bit RSA key and certificate on its own.
  * `verify_peer` - `true` if peer's certificate should be verified.
    Default OpenSSL verification is performed except that:
      * self-signed certificates are also accepted
      * verification fails if there is no peer cert

    Under the hood, `ExDTLS` uses `SSL_CTX_set_verify` with `SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT`.
    Note that if `verify_peer` is `false`, `get_peer_cert/1` called on `ExDTLS` working in the
    server mode, will always return `nil`. Defaults to `false`.
  """
  @spec init(opts :: opts_t) :: dtls()
  def init(opts) do
    srtp = Keyword.get(opts, :dtls_srtp, false)
    mode = Keyword.fetch!(opts, :mode)
    verify_peer = Keyword.get(opts, :verify_peer, false)

    cond do
      opts[:pkey] == nil and opts[:cert] == nil ->
        Native.init(mode, srtp, verify_peer)

      opts[:pkey] != nil and opts[:cert] != nil ->
        Native.init_from_key_cert(mode, srtp, verify_peer, opts[:pkey], opts[:cert])

      true ->
        raise ArgumentError, """
        Private key or certificate is nil. If you want private key and certificate
        to be generated don't pass any of them."
        """
    end
  end

  @doc """
  Generates a new key/certificate pair.

  This is always 2048-bit RSA key.

  `not_before` and `not_after` can be used to
  specify certificate duration in seconds.
  They have to fit into architecture-dependent integer size.
  Defaults to (-1 year) - (+ 1 year).

  Returns DER representation in binary format.
  """
  @spec generate_key_cert(integer(), integer()) :: {pkey :: binary(), cert :: binary()}
  defdelegate generate_key_cert(not_before \\ -31_536_000, not_after \\ 31_536_000), to: Native

  @doc """
  Gets current, local private key.

  Returns key specific representation in binary format.
  """
  @spec get_pkey(dtls()) :: binary()
  defdelegate get_pkey(dtls), to: Native

  @doc """
  Gets current, local certificate.

  Returns DER representation in binary format.
  """
  @spec get_cert(dtls()) :: binary()
  defdelegate get_cert(dtls), to: Native

  @doc """
  Gets peer certificate.

  Returns DER representation in binary format or `nil`
  when no certificate was presented by the peer or no connection
  was established.
  """
  @spec get_peer_cert(dtls()) :: binary() | nil
  def get_peer_cert(dtls) do
    case Native.get_peer_cert(dtls) do
      # Unifex can't return nil
      # see https://github.com/membraneframework/membrane_core/issues/684
      :"" -> nil
      other -> other
    end
  end

  @doc """
  Returns an SHA-256 digest of the DER representation of the X509 certificate.
  """
  @spec get_cert_fingerprint(binary()) :: binary()
  defdelegate get_cert_fingerprint(cert), to: Native

  @doc """
  Starts performing DTLS handshake.

  Generates initial DTLS packets that have to be passed to the second host.
  Has to be called by a host working in the client mode.

  `timeout` is a time in ms after which `handle_timeout/1` should be called.
  """
  @spec do_handshake(dtls()) ::
          {:ok, packets :: [binary()], timeout :: integer()} | {:error, :closed}
  defdelegate do_handshake(dtls), to: Native

  @doc """
  Writes data to the DTLS connection.

  Generates encrypted packets that need to be passed to the second host.
  """
  @spec write_data(dtls(), data :: binary()) ::
          {:ok, packets :: [binary()]} | {:error, :handshake_not_finished | :closed}
  defdelegate write_data(dtls, data), to: Native

  @doc """
  Handles peer's packets.

  When handshake is finished, calling `handle_data` will return `{:ok, binary()}`,
  which is decoded data.

  `:handshake_packets` contains handshake data that has to be sent to the peer.
  `:handshake_want_read` means some additional data is needed for continuing handshake.
  It can be returned when retransmitted packet was passed but timer didn't expired yet.
  `timeout` is a time in ms after which `handle_timeout/1` should be called.

  Both local and remote keying materials consist of `master key` and `master salt`.
  """
  @spec handle_data(dtls(), data :: binary()) ::
          {:ok, packets :: binary()}
          | :handshake_want_read
          | {:handshake_packets, packets :: [binary()], timeout :: integer()}
          | {:handshake_finished, local_keying_material :: binary(),
             remote_keying_material :: binary(), protection_profile_t(), packets :: [binary()]}
          | {:handshake_finished, local_keying_material :: binary(),
             remote_keying_material :: binary(), protection_profile_t()}
          | {:error, :handshake_error | :peer_closed_for_writing | :closed}
  def handle_data(dtls, packets) do
    case Native.handle_data(dtls, packets) do
      {:handshake_finished, lkm, rkm, protection_profile, []} ->
        {:handshake_finished, lkm, rkm, protection_profile}

      other ->
        other
    end
  end

  @doc """
  Handles timeout.

  If there is a timeout to handle, this function will return `packets` that has
  to be retransmitted and a new timeout in ms after which `handle_timeout/1` should
  be called once agian.

  If there is no timeout to handle, simple `{:ok, dtls()}` tuple is returned.
  """
  @spec handle_timeout(dtls()) ::
          :ok | {:retransmit, packets :: [binary()], timeout :: integer()} | {:error, :closed}
  defdelegate handle_timeout(dtls), to: Native

  @doc """
  Irreversibly closes DTLS session.

  If a handshake has been finished, this function will generate `close_notify` DTLS alert
  that should be sent to the other side.
  """
  @spec close(dtls()) :: {:ok, packets :: [binary()]}
  defdelegate close(dtls), to: Native, as: :exd_close
end
