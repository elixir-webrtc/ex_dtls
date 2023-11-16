module ExDTLS.Native

interface NIF

state_type "State"

spec init(client_mode :: bool, dtls_srtp :: bool) :: state

spec init_from_key_cert(client_mode :: bool, dtls_srtp :: bool, pkey :: payload, cert :: payload) ::
       state

spec generate_cert() :: cert :: payload

spec get_pkey(state) :: pkey :: payload

spec get_cert(state) :: cert :: payload

spec get_cert_fingerprint(state) :: fingerprint :: payload

spec do_handshake(state) :: {packets :: payload, timeout :: int}

spec handle_timeout(state) :: (:ok :: label) | {:retransmit :: label, packets :: payload, timeout :: int}

spec handle_data(state, packets :: payload) ::
       {:ok :: label, packets :: payload}
       | (:handshake_want_read :: label)
       | {:handshake_packets :: label, packets :: payload, timeout :: int}
       | {:handshake_finished :: label, client_keying_material :: payload,
          server_keying_material :: payload, protection_profile :: int, packets :: payload}
       | {:connection_closed :: label, :peer_closed_for_writing :: label}
