module DTLS.Native

interface CNode

state_type "State"

spec do_handshake(state) :: {:ok :: label}

sends {:handshake_finished :: label, keying_material :: string}
