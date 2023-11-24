module ExDTLS.Native

interface NIF

state_type "State"

spec init(mode :: atom, dtls_srtp :: bool, verify_peer :: bool) :: state

spec init_from_key_cert(mode :: atom, dtls_srtp :: bool, verify_peer :: bool, pkey :: payload, cert :: payload) ::
       state

spec generate_key_cert(not_before :: int64, not_after :: int64) :: {pkey :: payload, cert :: payload}

spec get_pkey(state) :: payload

spec get_cert(state) :: payload

spec get_peer_cert(state) :: payload | (nil :: label)

spec get_cert_fingerprint(payload) :: payload

spec do_handshake(state) :: {packets :: payload, timeout :: int}

spec handle_timeout(state) :: (:ok :: label) | {:retransmit :: label, packets :: payload, timeout :: int}

spec handle_data(state, packets :: payload) ::
       {:ok :: label, packets :: payload}
       | (:handshake_want_read :: label)
       | {:handshake_packets :: label, packets :: payload, timeout :: int}
       | {:handshake_finished :: label, client_keying_material :: payload,
          server_keying_material :: payload, protection_profile :: int, packets :: payload}
       | {:error :: label, :peer_closed_for_writing :: label}
       | {:error :: label, :handshake_error :: label
}
