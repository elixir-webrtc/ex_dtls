module ElixirDTLS.Native

interface CNode

state_type "State"

spec init(socket_path :: string, client_mode :: bool) :: {:ok :: label, state}

spec do_handshake(state) :: {:ok :: label, state}

spec get_cert_fingerprint(state) :: {:ok :: label, state, fingerprint :: string}
       | {:error :: label, :failed_to_get_fingerprint :: label}

sends {:handshake_finished :: label, keying_material :: string}
sends {:handshake_failed :: label, :peer_shutdown :: label}
sends {:handshake_failed :: label, :wbio_error :: label}
sends {:handshake_failed :: label, :rbio_error :: label}
sends {:handshake_failed :: label, :ssl_error :: label, err_code :: int}
