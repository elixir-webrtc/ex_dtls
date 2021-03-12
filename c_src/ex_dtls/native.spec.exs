module ExDTLS.Native

interface CNode

state_type "State"

spec init(client_mode :: bool, dtls_srtp :: bool) :: {:ok :: label, state}

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
                                           | {:error :: label, value :: int}
