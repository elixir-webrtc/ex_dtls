defmodule ExDTLS do
  @moduledoc """
  Module that allows performing DTLS handshake including DTLS-SRTP one.

  `ExDTLS` spawns CNode that uses OpenSSL functions to perform DTLS handshake.
  It doesn't create or require any socket. Instead it exchanges DTLS packets with its parent which is responsible for
  transporting them via net to the peer.
  """

  use GenServer

  require Unifex.CNode

  defmodule State do
    @moduledoc false

    @type t :: %__MODULE__{
            parent: pid(),
            cnode: Unifex.CNode.t()
          }
    defstruct parent: nil,
              cnode: nil
  end

  @doc """
  Starts ExDTLS GenServer process linked to the current process.

  - `parent` - a caller pid. This pid is used for sending messages from ExDTLS module to its parent.
  Possible messages are described in `do_handshake/1` documentation.
  - `client_mode` - true if ExDTLS module should work as a client or false if as a server.
  """
  @spec start_link(parent :: pid(), client_mode :: boolean()) :: {:ok, pid}
  def start_link(parent, client_mode) do
    GenServer.start_link(__MODULE__, {parent, client_mode})
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

  This function is required to call only once and only by a client.

  Calling this function will make ExDTLS module sending following messages:
    - `{:packets, data}` - generated DTLS packets that has to be sent by parent to the peer
    - `{:handshake_finished, keying_material}` - handshake finished successfully. `keying_material`
    is a String
    - `{:handshake_failed, :peer_shutdown}` - peer closed the connection
    - `{:handshake_failed, :wbio_error}` - error while using write BIO
    - `{:handshake_failed, :rbio_error}` - error while using read BIO
    - `{:handshake_failed, :ssl_error, err_code}` - executing SSL_do_handshake failed. `err_code`
    indicates error code returned by `SSL_get_error` function provided by OpenSSL.
  """
  @spec do_handshake(pid :: pid()) :: :ok
  def do_handshake(pid) do
    GenServer.cast(pid, :do_handshake)
  end

  @doc """
  Passes packets received from peer to the ExDTLS module.

  Each time parent of the ExDTLS receives DTLS packets it has to pass them to ExDTLS using this function.
  """
  @spec feed(pid :: pid(), data :: binary()) :: :ok
  def feed(pid, data) do
    GenServer.call(pid, {:feed, data})
  end

  # Server APi
  @doc false
  @impl true
  def init({parent, client_mode}) do
    {:ok, pid} = Unifex.CNode.start_link(:native)
    :ok = Unifex.CNode.call(pid, :init, [client_mode])
    state = %State{parent: parent, cnode: pid}
    {:ok, state}
  end

  @doc false
  @impl true
  def handle_cast(:do_handshake, %State{cnode: cnode} = state) do
    :ok = Unifex.CNode.call(cnode, :do_handshake)
    {:noreply, state}
  end

  @doc false
  @impl true
  def handle_call(:get_cert_fingerprint, _from, %State{cnode: cnode} = state) do
    {:ok, digest} = Unifex.CNode.call(cnode, :get_cert_fingerprint)
    {:reply, {:ok, hex_dump(digest)}, state}
  end

  @doc false
  @impl true
  def handle_call({:feed, data}, _from, %State{cnode: cnode} = state) do
    :ok = Unifex.CNode.call(cnode, :feed, [data])
    {:reply, :ok, state}
  end

  @doc false
  @impl true
  def handle_info(msg, %State{parent: parent} = state) do
    send(parent, msg)
    {:noreply, state}
  end

  defp hex_dump(digest_str) do
    digest_str
    |> :binary.bin_to_list()
    |> Enum.map_join(":", &:io_lib.format("~2.16.0B", [&1]))
  end
end
