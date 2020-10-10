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
  @spec get_cert_fingerprint(pid :: pid()) :: {:ok, fingerprint :: String.t()}
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
          | {:finished_with_packets, keying_material :: binary(), packets :: binary()}
          | {:finished, keying_material :: binary()}
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
    {:reply, msg, state}
  end

  @doc false
  @impl true
  def handle_call(:get_cert_fingerprint, _from, %State{cnode: cnode} = state) do
    {:ok, digest} = Unifex.CNode.call(cnode, :get_cert_fingerprint)
    {:reply, {:ok, hex_dump(digest)}, state}
  end

  defp hex_dump(digest_str) do
    digest_str
    |> :binary.bin_to_list()
    |> Enum.map_join(":", &:io_lib.format("~2.16.0B", [&1]))
  end
end
