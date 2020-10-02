module ExDTLS.Native

interface CNode

state_type "State"

spec init(client_mode :: bool, dtls_srtp :: bool) :: {:ok :: label, state}

spec get_cert_fingerprint(state) :: {:ok :: label, state, fingerprint :: string}
                                    | {:error :: label, :failed_to_get_fingerprint :: label}

spec do_handshake(state) :: {:ok :: label, state}

spec feed(state, data :: payload) :: {:ok :: label, state}

sends {:packets :: label, data :: payload}
sends {:handshake_finished :: label, keying_material :: string}
