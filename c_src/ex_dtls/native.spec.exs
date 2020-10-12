module ExDTLS.Native

interface CNode

state_type "State"

spec init(client_mode :: bool, dtls_srtp :: bool) :: {:ok :: label, state}

spec get_cert_fingerprint(state) :: {:ok :: label, state, fingerprint :: string}
                                    | {:error :: label, :failed_to_get_fingerprint :: label}

spec do_handshake(state, packets :: payload) :: {:ok :: label, state, packets :: payload}
                            | {:finished_with_packets :: label, state, keying_material :: string, packets :: payload}
                            | {:finished :: label, state, keying_material :: string}
