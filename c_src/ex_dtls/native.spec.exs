module ExDTLS.Native

interface CNode

state_type "State"

spec init(client_mode :: bool, dtls_srtp :: bool) :: {:ok :: label, state}

spec generate_cert() :: {:ok :: label, cert :: payload()}

spec set_cert(cert :: payload, state) :: {:ok :: label, state}
                                         | {:error :: label, :failed_to_decode_cert :: label}

spec get_cert(state) :: {:ok :: label, cert :: payload}

spec get_cert_fingerprint(state) :: {:ok :: label, state, fingerprint :: payload}

spec do_handshake(state) :: {:ok :: label, state, packets :: payload}

spec process(state, packets :: payload) :: {:ok :: label, state, packets :: payload}
                                           | (:hsk_want_read :: label)
                                           | {:hsk_packets :: label, state, packets :: payload}
                                           | {:hsk_finished :: label, state,
                                              client_keying_material :: payload,
                                              server_keying_material :: payload,
                                              protection_profile :: int,
                                              packets :: payload}
                                           | {:connection_closed :: label, :peer_closed_for_writing :: label}
