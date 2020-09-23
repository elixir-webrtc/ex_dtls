defmodule ElixirDTLS do
  @moduledoc"""
  Module that allows performing DTLS handshake including DTLS-SRTP one. Architecture is presented
  below:
  ```
  +------------+             +------------+
  | ElixirDTLS | - spawns -> |   CNode    |
  +------------+             | +--------+ |
                             | | Socket | |
                             | +--------+ |
                             +------------+
  ```
  `ElixirDTLS` spawns CNode that uses OpenSSL functions to perform DTLS handshake. Inside CNode
  there is exposed local domain socket (AF_UNIX). CNode will use it for sending and receiving
  generated DTLS packets. Example setup will look in this way:

  ```
  +------------+             +------------+               +------------+             +------------+
  | ElixirDTLS | - spawns -> |   CNode    |               |   CNode    | <- spawns - | ElixirDTLS |
  +------------+             | +--------+ |               | +--------+ |             +------------+
                             | | Socket | |               | | Socket | |
                             | +----|---+ |               | +----|---+ |
                             +------|-----+               +------|-----+
                                    |                            |
                                 packets                      packets
                                    |                            |
                             +--------------+             +--------------+
                             | User sockets | - packets - | User sockets |
                             +--------------+    (net)    +--------------+

  ```
  User has to create two sockets. The first one for exchanging DTLS packets with CNode and the
  second one for exchanging them with remote host over the net.
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

  @doc"""
  Starts DTLS GenServer process linked to current process.

  - `parent` - a caller pid. This pid is used for sending messages from DTLS module to its parent.
  Possible messages are described in `do_handshake/1` documentation.
  - `out_socket_path` - path under which DTLS module will create local domain socket for exposing
  and receiving DTLS packets,
  - `client_mode` - true if DTLS module should work as a client or false if as a server

  After this function returns user can connect to DTLS local domain socket created under
  `out_socket_path`.
  """
  @spec start_link(parent :: pid, out_socket_path :: String.t(), client_mode :: boolean) :: {:ok, pid}
  def start_link(parent, out_socket_path, client_mode) do
    GenServer.start_link(__MODULE__, {parent, out_socket_path, client_mode})
  end

  @doc"""
  Calling this function when module is working in a client mode will cause starting DTLS handshake.

  Calling this function when module is working in a server mode will start server waiting for
  incoming handshake.

  Calls on both sides are required. Order of calls doesn't matter.

  Calling this function will make DTLS module sending some messages. Following messages can be
  received by parent of DTLS module:
    - `{:handshake_finished, keying_material}` - handshake finished successfully. `keying_material`
    is a String.
    - `{:handshake_failed, :peer_shutdown}` - peer closed the connection.
    - `{:handshake_failed, :wbio_error}` - error while using write BIO.
    - `{:handshake_failed, :rbio_error}` - error while using read BIO.
    - `{:handshake_failed, :ssl_error, err_code}` - executing SSL_do_handshake failed. `err_code`
    indicates error code returned by `SSL_get_error` function provided by OpenSSL.
  """
  def do_handshake(pid) do
    GenServer.cast(pid, :do_handshake)
  end

  # Server APi
  @doc false
  @impl true
  def init({parent, out_socket_path, client_mode}) do
    state = init_socket(out_socket_path, client_mode)
    state = %State{state | parent: parent}
    {:ok, state}
  end

  defp init_socket(socket_path, client_mode) do
    {:ok, pid} = Unifex.CNode.start_link(:native)
    :ok = Unifex.CNode.call(pid, :init, [socket_path, client_mode])
    %State{cnode: pid}
  end

  @doc false
  @impl true
  def handle_cast(:do_handshake, %State{cnode: cnode} = state) do
    :ok = Unifex.CNode.call(cnode, :do_handshake)
    {:noreply, state}
  end

  @doc false
  @impl true
  def handle_info(msg, %State{parent: parent} = state) do
    send(parent, msg)
    {:noreply, state}
  end
end
