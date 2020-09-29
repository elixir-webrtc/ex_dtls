module ExDTLS.Native

interface CNode

state_type "State"

spec init(client_mode :: bool) :: {:ok :: label, state}

spec get_cert_fingerprint(state) :: {:ok :: label, state, fingerprint :: string}
                                    | {:error :: label, :failed_to_get_fingerprint :: label}

spec do_handshake(state) :: {:ok :: label, state}

spec feed(state, data :: payload) :: {:ok :: label, state}

sends {:packets :: label, data :: payload}
sends {:handshake_finished :: label, keying_material :: string}
sends {:handshake_failed :: label, :peer_shutdown :: label}
sends {:handshake_failed :: label, :wbio_error :: label}
sends {:handshake_failed :: label, :rbio_error :: label}
sends {:handshake_failed :: label, :ssl_error :: label, err_code :: int}
