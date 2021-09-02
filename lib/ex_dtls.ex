defmodule ExDTLS do
  @moduledoc """
  Module that allows performing DTLS handshake including DTLS-SRTP one.

  `ExDTLS` spawns CNode that uses OpenSSL functions to perform DTLS handshake.
  It doesn't create or require any socket. Instead it returns generated DTLS packets which then have
  to be transported to the peer.
  """

  use GenServer

  require Unifex.CNode

  defmodule State do
    @moduledoc false

    @type t :: %__MODULE__{
            cnode: Unifex.CNode.t(),
            client_mode: boolean(),
            finished?: boolean()
          }
    defstruct cnode: nil,
              client_mode: false,
              finished?: false
  end

  @typedoc """
  Type describing ExDTLS configuration.

  It's a keyword list containing the following keys:
  * `client_mode` - true if ExDTLS module should work as a client or false if as a server
  * `dtls_srtp` - true if DTLS-SRTP handshake should be performed or false if a normal one
  * `pkey` - private key to use in this SSL context. Must corespond to `cert`.
  * `cert` - certificate to use in this SSL context. Must corespond to `pkey`.

  `pkey` and `cert` are optional. If not provided `ExDTLS` will generate them.
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

  @doc """
  Starts ExDTLS GenServer process linked to the current process.
  """
  @spec start_link(opts :: opts_t) :: {:ok, pid}
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
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
  """
  @spec do_handshake(pid :: pid(), packets :: binary()) :: :ok | {:ok, packets :: binary()}

  def do_handshake(pid, packets \\ <<>>) do
    GenServer.call(pid, {:do_handshake, packets})
  end

  @doc """
  Processes peer's packets.

  If handshake is finished it returns `{:ok, binary()}` which is decoded data
  or `{:error, value}` if error occurred.

  `{:handshake_packets, binary()}` contains handshake data that has to be sent to the peer.
  `:handshake_want_read` means some additional data is needed for continuing handshake. It can be returned
  when retransmitted packet was passed but timer didn't expired yet.
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

  # Server APi
  @impl true
  def init(opts) do
    {:ok, pid} = Unifex.CNode.start_link(:native)

    cond do
      opts[:pkey] == nil and opts[:cert] == nil ->
        :ok = Unifex.CNode.call(pid, :init, [opts[:client_mode], opts[:dtls_srtp]])

      opts[:pkey] != nil and opts[:cert] != nil ->
        :ok =
          Unifex.CNode.call(pid, :init_from_key_cert, [
            opts[:client_mode],
            opts[:dtls_srtp],
            opts[:pkey],
            opts[:cert]
          ])

      true ->
        raise("""
        Private key or certificate is nil. If you want private key and certificate
        to be generated don't pass any of them."
        """)
    end

    state = %State{cnode: pid, client_mode: opts[:client_mode]}
    {:ok, state}
  end

  @impl true
  def handle_call({:do_handshake, packets}, _from, %State{cnode: cnode} = state) do
    {:ok, _packets} = msg = Unifex.CNode.call(cnode, :do_handshake, [packets])
    {:reply, msg, state}
  end

  @impl true
  def handle_call({:process, packets}, {parent, _alias}, %State{cnode: cnode} = state) do
    msg = Unifex.CNode.call(cnode, :process, [packets])

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
  def handle_call(:generate_cert, _from, %State{cnode: cnode} = state) do
    {:ok, cert} = Unifex.CNode.call(cnode, :generate_cert)
    {:reply, {:ok, cert}, state}
  end

  @impl true
  def handle_call(:get_cert_fingerprint, _from, %State{cnode: cnode} = state) do
    {:ok, digest} = Unifex.CNode.call(cnode, :get_cert_fingerprint)
    {:reply, {:ok, digest}, state}
  end

  @impl true
  def handle_call(:get_pkey, _from, %State{cnode: cnode} = state),
    do: {:reply, Unifex.CNode.call(cnode, :get_pkey), state}

  @impl true
  def handle_call(:get_cert, _from, %State{cnode: cnode} = state),
    do: {:reply, Unifex.CNode.call(cnode, :get_cert), state}

  @impl true
  def handle_info({:handle_timeout, reply_pid, timeout}, %State{cnode: cnode} = state) do
    case Unifex.CNode.call(cnode, :handle_timeout) do
      {:retransmit, packets} when timeout < @max_retransmit_timeout and not state.finished? ->
        send(reply_pid, {:retransmit, 1, packets})
        Process.send_after(self(), {:handle_timeout, reply_pid, timeout * 2}, timeout * 1000)

      _other when timeout >= @max_retransmit_timeout and not state.finished? ->
        raise "Reach max retransmit timeout"

      _other ->
        nil
    end

    {:noreply, state}
  end

  @impl true
  def terminate(_reason, %State{cnode: cnode}) do
    Unifex.CNode.stop(cnode)
  end

  defp get_local_and_remote_km(client_keying_material, server_keying_material, true),
    do: {client_keying_material, server_keying_material}

  defp get_local_and_remote_km(client_keying_material, server_keying_material, false),
    do: {server_keying_material, client_keying_material}
end
