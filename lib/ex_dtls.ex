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
          client_mode: boolean(),
          dtls_srtp: boolean(),
          pkey: binary(),
          cert: binary()
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
  * `client_mode` - `true` if ExDTLS module should work as a client or `false` if as a server
  * `dtls_srtp` - `true` if DTLS-SRTP handshake should be performed or `false` if a normal one
  * `pkey` - private key to use in this SSL context. Must correspond to `cert`
  * `cert` - certificate to use in this SSL context. Must correspond to `pkey`

  If both `pkey` and `cert` are not passed `ExDTLS` will generate key and certificate on its own.
  """
  @spec init(opts :: opts_t) :: dtls()
  def init(opts) do
    srtp? = Keyword.get(opts, :dtls_srtp, false)
    client? = Keyword.fetch!(opts, :client_mode)

    cond do
      opts[:pkey] == nil and opts[:cert] == nil ->
        Native.init(client?, srtp?)

      opts[:pkey] != nil and opts[:cert] != nil ->
        Native.init_from_key_cert(client?, srtp?, opts[:pkey], opts[:cert])

      true ->
        raise ArgumentError, """
        Private key or certificate is nil. If you want private key and certificate
        to be generated don't pass any of them."
        """
    end
  end

  @doc """
  Generates new certificate.

  Returns DER representation in binary format.
  """
  @spec generate_cert() :: binary()
  defdelegate generate_cert(), to: Native

  @doc """
  Gets current private key.

  Returns key specific representation in binary format.
  """
  @spec get_pkey(dtls()) :: binary()
  defdelegate get_pkey(dtls), to: Native

  @doc """
  Gets current certificate.

  Returns DER representation in binary format.
  """
  @spec get_cert(dtls()) :: binary()
  defdelegate get_cert(dtls), to: Native

  @doc """
  Returns a digest of the DER representation of the X509 certificate.
  """
  @spec get_cert_fingerprint(dtls()) :: binary
  defdelegate get_cert_fingerprint(dtls), to: Native

  @doc """
  Starts performing DTLS handshake.

  Generates initial DTLS packets that have to be passed to the second host.
  Has to be called by a host working in the client mode.

  `timeout` is a time in ms after which `handle_timeout/1` should be called.
  """
  @spec do_handshake(dtls()) :: {packets :: binary(), timeout :: integer()}
  defdelegate do_handshake(dtls), to: Native

  @doc """
  Handles peer's packets.

  If handshake is finished it returns `{:ok, binary()}` which is decoded data
  or `{:error, value}` if error occurred.

  `:handshake_packets` contains handshake data that has to be sent to the peer.
  `:handshake_want_read` means some additional data is needed for continuing handshake. 
  It can be returned when retransmitted packet was passed but timer didn't expired yet.
  `timeout` is a time in ms after which `handle_timeout/1` should be called.

  Both local and remote keying materials consist of `master key` and `master salt`.
  """
  @spec handle_data(dtls(), packets :: binary()) ::
          {:ok, packets :: binary()}
          | :handshake_want_read
          | {:handshake_packets, packets :: binary(), timeout :: integer()}
          | {:handshake_finished, local_keying_material :: binary(),
             remote_keying_material :: binary(), protection_profile_t(), packets :: binary()}
          | {:handshake_finished, local_keying_material :: binary(),
             remote_keying_material :: binary(), protection_profile_t()}
          | {:connection_closed, reason :: atom()}
  def handle_data(dtls, packets) do
    case Native.handle_data(dtls, packets) do
      {:handshake_finished, lkm, rkm, protection_profile, <<>>} ->
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
  @spec handle_timeout(dtls()) :: :ok | {:retransmit, packets :: binary(), timeout :: integer()}
  defdelegate handle_timeout(dtls), to: Native
end
