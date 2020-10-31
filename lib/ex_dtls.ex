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
            cnode: Unifex.CNode.t()
          }
    defstruct cnode: nil
  end

  @typedoc """
  Type describing ExDTLS configuration.

  It's a keyword list containing the following keys:
  * `client_mode` - true if ExDTLS module should work as a client or false if as a server
  * `dtls_srtp` - true if DTLS-SRTP handshake should be performed or false if a normal one
  """
  @type opts_t :: [
          client_mode: boolean(),
          dtls_srtp: boolean()
        ]

  @typedoc """
  Supported protection profiles.

  For meaning of these values please refer to
  https://www.iana.org/assignments/srtp-protection/srtp-protection.xhtml
  """
  @type protection_profile_t() :: 0x01 | 0x02 | 0x07 | 0x08

  @typedoc """
  Type describing data returned after successful handshake.

  Both client and server keying materials consist of `master key` and `master salt`.
  `client_keying_material` belongs to a peer working in a `client_mode`.
  """
  @type handshake_data_t ::
          {client_keying_material :: binary(), server_keying_material :: binary(),
           protection_profile :: protection_profile_t()}

  @doc """
  Starts ExDTLS GenServer process linked to the current process.
  """
  @spec start_link(opts :: opts_t) :: {:ok, pid}
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
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

  This function has to be called without any `packets` by host working in the client mode at first.
  This will return initial DTLS packets that have to be passed to the second host.
  Then both peers have to call this function to process incoming packets and generate outgoing ones.

  A peer that finishes handshake successfully first will return
  `{:finished_with_packets, keying_material, packets}` message. Received packets have to be
  once again passed to a second peer so it can finish its handshake too and return
  `{:finished, keying_material}` message.
  """
  @spec do_handshake(pid :: pid(), packets :: binary()) ::
          {:ok, packets :: binary()}
          | {:finished_with_packets, handshake_data_t(), packets :: binary()}
          | {:finished, handshake_data_t()}
  def do_handshake(pid, packets \\ <<>>) do
    GenServer.call(pid, {:do_handshake, packets})
  end

  # Server APi
  @doc false
  @impl true
  def init(opts) do
    {:ok, pid} = Unifex.CNode.start_link(:native)
    :ok = Unifex.CNode.call(pid, :init, [opts[:client_mode], opts[:dtls_srtp]])
    state = %State{cnode: pid}
    {:ok, state}
  end

  @doc false
  @impl true
  def handle_call({:do_handshake, packets}, _from, %State{cnode: cnode} = state) do
    msg = Unifex.CNode.call(cnode, :do_handshake, [packets])

    case msg do
      {:ok, _packets} ->
        {:reply, msg, state}

      {:finished_with_packets, client_keying_material, server_keying_material, protection_profile,
       packets} ->
        handshake_data = {client_keying_material, server_keying_material, protection_profile}
        msg = {:finished_with_packets, handshake_data, packets}
        {:reply, msg, state}

      {:finished, client_keying_material, server_keying_material, protection_profile} ->
        handshake_data = {client_keying_material, server_keying_material, protection_profile}
        msg = {:finished, handshake_data}
        {:reply, msg, state}
    end
  end

  @doc false
  @impl true
  def handle_call(:get_cert_fingerprint, _from, %State{cnode: cnode} = state) do
    {:ok, digest} = Unifex.CNode.call(cnode, :get_cert_fingerprint)
    {:reply, {:ok, digest}, state}
  end
end
