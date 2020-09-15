module DTLS.Native

interface CNode

state_type "State"

spec init(socket_path :: string) :: {:ok :: label, state}

spec do_handshake(state) :: {:ok :: label, state}

sends {:handshake_finished :: label, keying_material :: string}
