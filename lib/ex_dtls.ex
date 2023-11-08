defmodule ExDTLS do
  @moduledoc """
  Module that allows performing DTLS handshake including a DTLS-SRTP one.

  `ExDTLS` executes native OpenSSL functions to perform DTLS handshake.
  It doesn't create or require any socket. Instead, it returns generated DTLS packets which then have
  to be transported to the peer.
  """

  use GenServer

  defmodule State do
    @moduledoc false

    @type t :: %__MODULE__{
            client_mode: boolean(),
            finished?: boolean(),
            native: reference()
          }
    defstruct client_mode: false,
              finished?: false,
              native: nil
  end

  @typedoc """
  Type describing ExDTLS configuration.

  See `start_link/1` for the meaning of each option
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
  Type describing data returned after successful handshake.

  Both local and remote keying materials consist of `master key` and `master salt`.
  """
  @type handshake_data_t ::
          {local_keying_material :: binary(), remote_keying_material :: binary(),
           protection_profile :: protection_profile_t()}

  @typedoc """
  Messsage sent when some packets should be retransmitted.

  When ExDTLS generates handshake packets and don't receive
  a response fast enough, it will ask for sending those
  packets once again.
  """
  @type retransmit_msg_t :: {:ex_dtls, pid(), {:retransmit, binary()}}

  @doc """
  Starts ExDTLS GenServer process linked to the current process.

  Accepts a keyword list with the following options (`t:opts_t/0`):
  * `client_mode` - `true` if ExDTLS module should work as a client or `false` if as a server
  * `dtls_srtp` - `true` if DTLS-SRTP handshake should be performed or `false` if a normal one
  * `pkey` - private key to use in this SSL context. Must correspond to `cert`
  * `cert` - certificate to use in this SSL context. Must correspond to `pkey`

  If both `pkey` and `cert` are not passed `ExDTLS` will generate key and certificate on its own.
  """
  @spec start_link(opts :: opts_t) :: {:ok, pid}
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @doc """
  Works similarly to `start_link/1`, but does not link to the current process.
  """
  @spec start(opts :: opts_t) :: {:ok, pid}
  def start(opts) do
    GenServer.start(__MODULE__, opts)
  end

  @doc """
  Generates new certificate.

  Returns DER representation in binary format.
  """
  @spec generate_cert(pid :: pid()) :: cert :: binary()
  def generate_cert(pid) do
    GenServer.call(pid, :generate_cert)
  end

  @doc """
  Gets current private key.

  Returns key specific representation in binary format.
  """
  @spec get_pkey(pid :: pid()) :: pkey :: {:ok, binary()}
  def get_pkey(pid) do
    GenServer.call(pid, :get_pkey)
  end

  @doc """
  Gets current certificate.

  Returns DER representation in binary format.
  """
  @spec get_cert(pid :: pid()) :: cert :: {:ok, binary()}
  def get_cert(pid) do
    GenServer.call(pid, :get_cert)
  end

  @doc """
  Returns a digest of the DER representation of the X509 certificate.
  """
  @spec get_cert_fingerprint(pid :: pid()) :: {:ok, fingerprint :: binary()}
  def get_cert_fingerprint(pid) do
    GenServer.call(pid, :get_cert_fingerprint)
  end

  @doc """
  Starts performing DTLS handshake.

  Generates initial DTLS packets that have to be passed to the second host.
  Has to be called by a host working in the client mode.

  Calling this function may trigger retransmission request.
  See `t:retransmit_msg_t/0`.
  """
  @spec do_handshake(pid :: pid()) :: :ok | {:ok, packets :: binary()}
  def do_handshake(pid) do
    GenServer.call(pid, :do_handshake)
  end

  @doc """
  Processes peer's packets.

  If handshake is finished it returns `{:ok, binary()}` which is decoded data
  or `{:error, value}` if error occurred.

  `{:handshake_packets, binary()}` contains handshake data that has to be sent to the peer.
  `:handshake_want_read` means some additional data is needed for continuing handshake. 
  It can be returned when retransmitted packet was passed but timer didn't expired yet.

  Calling this function may trigger retransmission request.
  See `t:retransmit_msg_t/0`.
  """
  @spec process(pid :: pid(), packets :: binary()) ::
          {:ok, packets :: binary()}
          | :handshake_want_read
          | {:handshake_packets, packets :: binary()}
          | {:handshake_finished, handshake_data_t(), packets :: binary()}
          | {:handshake_finished, handshake_data_t()}
          | {:connection_closed, reason :: atom()}
  def process(pid, packets) do
    GenServer.call(pid, {:process, packets})
  end

  @doc """
  Stops ExDTLS instance.
  """
  @spec stop(pid :: pid()) :: :ok
  def stop(pid) do
    GenServer.stop(pid, :normal)
  end

  @max_retransmit_timeout 60

  @doc """
  Returns max retransmission timeout after which `ExDTLS` will raise an error.

  Timer starts at one second and is doubled each time `ExDTLS` does not receive a response.
  After reaching `@max_retransmission_timeout` `ExDTLS` will raise an error.
  """
  @spec get_max_retransmit_timeout() :: non_neg_integer()
  def get_max_retransmit_timeout(), do: @max_retransmit_timeout

  # Server APi
  @impl true
  def init(opts) do
    srtp? = Keyword.get(opts, :dtls_srtp, false)
    client? = Keyword.fetch!(opts, :client_mode)

    state = %State{client_mode: client?}

    {:ok, state} =
      cond do
        opts[:pkey] == nil and opts[:cert] == nil ->
          call(:init, [client?, srtp?], state)

        opts[:pkey] != nil and opts[:cert] != nil ->
          call(
            :init_from_key_cert,
            [
              client?,
              srtp?,
              opts[:pkey],
              opts[:cert]
            ],
            state
          )

        true ->
          raise ArgumentError, """
          Private key or certificate is nil. If you want private key and certificate
          to be generated don't pass any of them."
          """
      end

    {:ok, state}
  end

  @impl true
  def handle_call(:do_handshake, {parent, _alias}, state) do
    {{:ok, _packets} = msg, state} = call(:do_handshake, [], state)
    Process.send_after(self(), {:handle_timeout, parent, 2}, 1000)
    {:reply, msg, state}
  end

  @impl true
  def handle_call({:process, packets}, {parent, _alias}, state) do
    {msg, state} = call(:process, [packets], state)

    {message, state} =
      case msg do
        {:ok, _packets} = msg ->
          {msg, state}

        :hsk_want_read ->
          {:handshake_want_read, state}

        {:hsk_packets, packets} ->
          Process.send_after(self(), {:handle_timeout, parent, 2}, 1000)
          {{:handshake_packets, packets}, state}

        {:hsk_finished, client_keying_material, server_keying_material, protection_profile, <<>>} ->
          {local_km, remote_km} =
            get_local_and_remote_km(
              client_keying_material,
              server_keying_material,
              state.client_mode
            )

          handshake_data = {local_km, remote_km, protection_profile}
          msg = {:handshake_finished, handshake_data}
          {msg, state}

        {:hsk_finished, client_keying_material, server_keying_material, protection_profile,
         packets} ->
          {local_km, remote_km} =
            get_local_and_remote_km(
              client_keying_material,
              server_keying_material,
              state.client_mode
            )

          handshake_data = {local_km, remote_km, protection_profile}
          msg = {:handshake_finished, handshake_data, packets}
          state = %{state | finished?: true}
          {msg, state}

        {:connection_closed, _reason} = msg ->
          {msg, state}
      end

    {:reply, message, state}
  end

  @impl true
  def handle_call(:generate_cert, _from, state) do
    {{:ok, cert}, state} = call(:generate_cert, [], state)
    {:reply, {:ok, cert}, state}
  end

  @impl true
  def handle_call(:get_cert_fingerprint, _from, state) do
    {{:ok, digest}, state} = call(:get_cert_fingerprint, [], state)
    {:reply, {:ok, digest}, state}
  end

  @impl true
  def handle_call(:get_pkey, _from, state) do
    {{:ok, pkey}, state} = call(:get_pkey, [], state)
    {:reply, {:ok, pkey}, state}
  end

  @impl true
  def handle_call(:get_cert, _from, state) do
    {{:ok, cert}, state} = call(:get_cert, [], state)
    {:reply, {:ok, cert}, state}
  end

  @impl true
  def handle_info({:handle_timeout, _reply_pid, timeout}, %State{finished?: false})
      when timeout >= @max_retransmit_timeout,
      do: raise("DTLS handshake reached max retransmission number")

  @impl true
  def handle_info({:handle_timeout, reply_pid, timeout}, %State{finished?: false} = state)
      when timeout < @max_retransmit_timeout do
    case call(:handle_timeout, [], state) do
      {{:retransmit, packets}, _state} ->
        send(reply_pid, {:ex_dtls, self(), {:retransmit, packets}})
        Process.send_after(self(), {:handle_timeout, reply_pid, timeout * 2}, timeout * 1000)

      _other ->
        nil
    end

    {:noreply, state}
  end

  @impl true
  def handle_info({:handle_timeout, _reply_pid, _timeout}, state), do: {:noreply, state}

  defp call(func, args, state) when func in [:init, :init_from_key_cert] do
    {ret, native} = apply(ExDTLS.Native, func, args)
    {ret, %{state | native: native}}
  end

  defp call(func, args, state) do
    {ret, native} = apply(ExDTLS.Native, func, [state.native | args])
    {ret, %{state | native: native}}
  end

  defp get_local_and_remote_km(client_keying_material, server_keying_material, true),
    do: {client_keying_material, server_keying_material}

  defp get_local_and_remote_km(client_keying_material, server_keying_material, false),
    do: {server_keying_material, client_keying_material}
end
