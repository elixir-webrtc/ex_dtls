module ElixirDTLS.Native

interface CNode

state_type "State"

spec init(socket_path :: string, client_mode :: bool) :: {:ok :: label, state}

spec do_handshake(state) :: {:ok :: label, state}

sends {:handshake_finished :: label, keying_material :: string}
sends {:handshake_failed :: label, :peer_shutdown :: label}
sends {:handshake_failed :: label, error :: int}
