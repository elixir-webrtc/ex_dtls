#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "dyn_buff.h"
#include "native.h"

static void ssl_info_cb(const SSL *ssl, int where, int ret);
static int verify_cb(int preverify_ok, X509_STORE_CTX *ctx);
static int read_pending_data(UnifexPayload *gen_packets, int pending_data_len,
                             State *state);
static void cert_to_payload(UnifexEnv *env, X509 *x509, UnifexPayload *payload);
static void pkey_to_payload(UnifexEnv *env, EVP_PKEY *pkey,
                            UnifexPayload *payload);

UNIFEX_TERM do_init(UnifexEnv *env, char *mode, int dtls_srtp, int verify_peer,
                    EVP_PKEY *pkey, X509 *x509);
UNIFEX_TERM handle_regular_read(State *state, char data[], int ret);
UNIFEX_TERM handle_read_error(State *state, int ret);
UNIFEX_TERM handle_handshake_in_progress(State *state, int ret);
UNIFEX_TERM handle_handshake_finished(State *state);

int handle_load(UnifexEnv *env, void **priv_data) {
  UNIFEX_UNUSED(env);
  UNIFEX_UNUSED(priv_data);

  FILE *urandom = fopen("/dev/urandom", "r");
  if (urandom == NULL) {
    DEBUG("Cannot open /dev/urandom");
    return -1;
  }

  unsigned int seed;
  int bytes = fread(&seed, sizeof(unsigned int), 1, urandom);
  if (bytes != 1) {
    DEBUG("Cannot read random bytes from /dev/urandom");
    return -1;
  }

  DEBUG("Random seed: %u\n", seed);

  srand(seed);

  return 0;
}

UNIFEX_TERM init(UnifexEnv *env, char *mode_str, int dtls_srtp,
                 int verify_peer) {
  UNIFEX_TERM res_term;

  EVP_PKEY *pkey = gen_key();
  if (pkey == NULL) {
    res_term = unifex_raise(env, "Cannot generate key pair");
    goto exit;
  }

  X509 *x509 = gen_cert(pkey, -31536000L, 31536000L);
  if (x509 == NULL) {
    res_term = unifex_raise(env, "Cannot generate cert");
    goto exit;
  }

  res_term = do_init(env, mode_str, dtls_srtp, verify_peer, pkey, x509);
exit:
  return res_term;
}

UNIFEX_TERM init_from_key_cert(UnifexEnv *env, char *mode_str, int dtls_srtp,
                               int verify_peer, UnifexPayload *pkey,
                               UnifexPayload *cert) {
  UNIFEX_TERM res_term;

  EVP_PKEY *evp_pkey = decode_pkey(pkey->data, pkey->size);
  if (evp_pkey == NULL) {
    res_term = unifex_raise(env, "Cannot decode pkey");
    goto exit;
  }

  X509 *x509 = decode_cert(cert->data, cert->size);
  if (x509 == NULL) {
    res_term = unifex_raise(env, "Cannot decode cert");
    goto exit;
  }

  res_term = do_init(env, mode_str, dtls_srtp, verify_peer, evp_pkey, x509);
exit:
  return res_term;
}

UNIFEX_TERM do_init(UnifexEnv *env, char *mode_str, int dtls_srtp,
                    int verify_peer, EVP_PKEY *pkey, X509 *x509) {
  UNIFEX_TERM res_term;

  State *state = unifex_alloc_state(env);
  state->ssl_ctx = NULL;
  state->ssl = NULL;
  state->pkey = NULL;
  state->x509 = NULL;
  state->mode = 0;
  state->hsk_finished = 0;
  state->env = unifex_alloc_env(env);

  int mode;
  if (strcmp(mode_str, "client") == 0) {
    mode = MODE_CLIENT;
  } else if (strcmp(mode_str, "server") == 0) {
    mode = MODE_SERVER;
  } else {
    res_term = unifex_raise(env, "Invalid DTLS mode");
    goto exit;
  }
  state->mode = mode;

  state->ssl_ctx = create_ctx(dtls_srtp);
  if (state->ssl_ctx == NULL) {
    res_term = unifex_raise(env, "Cannot create ssl_ctx");
    goto exit;
  }

  if (verify_peer == 1) {
    SSL_CTX_set_verify(state->ssl_ctx,
                       SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_PEER,
                       verify_cb);
  }

  state->pkey = pkey;
  if (SSL_CTX_use_PrivateKey(state->ssl_ctx, state->pkey) != 1) {
    res_term = unifex_raise(env, "Cannot set private key");
    goto exit;
  }

  state->x509 = x509;
  if (SSL_CTX_use_certificate(state->ssl_ctx, state->x509) != 1) {
    res_term = unifex_raise(env, "Cannot set cert");
    goto exit;
  }

  state->ssl = create_ssl(state->ssl_ctx, state->mode);
  if (state->ssl == NULL) {
    res_term = unifex_raise(env, "Cannot create ssl");
    goto exit;
  }

  state->hsk_finished = 0;
  SSL_set_info_callback(state->ssl, ssl_info_cb);
  res_term = init_from_key_cert_result(env, state);

exit:
  unifex_release_state(env, state);
  return res_term;
}

UNIFEX_TERM generate_key_cert(UnifexEnv *env, int not_before, int not_after) {
  UnifexPayload pkey_payload;
  UnifexPayload cert_payload;

  EVP_PKEY *pkey = gen_key();
  X509 *cert = gen_cert(pkey, (long)not_before, (long)not_after);

  pkey_to_payload(env, pkey, &pkey_payload);
  cert_to_payload(env, cert, &cert_payload);

  UNIFEX_TERM res_term =
      generate_key_cert_result(env, &pkey_payload, &cert_payload);
  unifex_payload_release(&pkey_payload);
  unifex_payload_release(&cert_payload);
  return res_term;
}

UNIFEX_TERM get_pkey(UnifexEnv *env, State *state) {
  UnifexPayload payload;
  pkey_to_payload(env, state->pkey, &payload);
  UNIFEX_TERM res_term = get_pkey_result(env, &payload);
  unifex_payload_release(&payload);
  return res_term;
}

UNIFEX_TERM get_cert(UnifexEnv *env, State *state) {
  UnifexPayload payload;
  cert_to_payload(env, state->x509, &payload);
  UNIFEX_TERM res_term = get_cert_result(env, &payload);
  unifex_payload_release(&payload);
  return res_term;
}

UNIFEX_TERM get_peer_cert(UnifexEnv *env, State *state) {
  UNIFEX_TERM res_term;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  X509 *x509 = SSL_get0_peer_certificate(state->ssl);
#else
  X509 *x509 = SSL_get_peer_certificate(state->ssl);
#endif

  if (x509 != NULL) {
    UnifexPayload payload;
    cert_to_payload(env, x509, &payload);
    res_term = get_peer_cert_result(env, &payload);
    unifex_payload_release(&payload);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    X509_free(x509);
#endif

  } else {
    res_term = get_peer_cert_result_nil(env);
  }

  return res_term;
}

UNIFEX_TERM get_cert_fingerprint(UnifexEnv *env, UnifexPayload *cert) {
  UNIFEX_TERM res_term;
  unsigned char md[EVP_MAX_MD_SIZE] = {0};
  unsigned int size;

  X509 *x509 = decode_cert(cert->data, cert->size);
  if (x509 == NULL) {
    res_term = unifex_raise(env, "Cannot decode cert");
    goto exit;
  }

  if (X509_digest(x509, EVP_sha256(), md, &size) != 1) {
    return unifex_raise(env, "Can't get cert fingerprint");
  }
  UnifexPayload payload;
  unifex_payload_alloc(env, UNIFEX_PAYLOAD_BINARY, size, &payload);
  memcpy(payload.data, md, size);
  payload.size = size;
  res_term = get_cert_fingerprint_result(env, &payload);
  unifex_payload_release(&payload);
exit:
  return res_term;
}

UNIFEX_TERM do_handshake(UnifexEnv *env, State *state) {
  SSL_do_handshake(state->ssl);

  size_t pending_data_len = BIO_ctrl_pending(SSL_get_wbio(state->ssl));
  if (pending_data_len > 0) {
    DEBUG("WBIO: pending data: %ld bytes", pending_data_len);

    char *pending_data = (char *)malloc(pending_data_len * sizeof(char));
    memset(pending_data, 0, pending_data_len);
    BIO *wbio = SSL_get_wbio(state->ssl);
    int read_bytes = BIO_read(wbio, pending_data, pending_data_len);
    if (read_bytes <= 0) {
      DEBUG("WBIO: read error");
      return unifex_raise(state->env, "Handshake failed: write BIO error");
    } else {
      DEBUG("WBIO: read: %d bytes", read_bytes);
      UnifexPayload gen_packets;
      unifex_payload_alloc(env, UNIFEX_PAYLOAD_BINARY, pending_data_len,
                           &gen_packets);
      memcpy(gen_packets.data, pending_data, pending_data_len);
      gen_packets.size = (unsigned int)pending_data_len;
      int timeout = get_timeout(state->ssl);
      UNIFEX_TERM res_term = do_handshake_result(env, &gen_packets, timeout);
      unifex_payload_release(&gen_packets);
      return res_term;
    }
  }

  return unifex_raise(state->env, "Handshake failed: no packets generated");
}

UNIFEX_TERM write_data(UnifexEnv *env, State *state, UnifexPayload *payload) {
  if (state->hsk_finished != 1) {
    DEBUG("Cannot write, handshake not finished");
    return write_data_result_error_handshake_not_finished(env);
  }

  int ret = SSL_write(state->ssl, payload->data, payload->size);
  if (ret <= 0) {
    DEBUG("Unable to write data");
    return unifex_raise(env, "Unable to write data");
  }

  BIO *wbio = SSL_get_wbio(state->ssl);
  size_t pending_data_len = BIO_ctrl_pending(wbio);
  if (pending_data_len == 0) {
    DEBUG("No data to read from BIO after writing");
    return unifex_raise(env, "No data to read from BIO after writing");
  }

  UnifexPayload res_payload;
  unifex_payload_alloc(env, UNIFEX_PAYLOAD_BINARY, pending_data_len, &res_payload);

  int read_bytes = BIO_read(wbio, res_payload.data, pending_data_len);
  if (read_bytes <= 0 || (size_t) read_bytes != pending_data_len) {
    DEBUG("Unable to read data from BIO after writing");
    return unifex_raise(env, "Unable to read data from BIO after writing");
  }

  DEBUG("Wrote %d bytes of data", read_bytes);
  res_payload.size = (unsigned int) pending_data_len;
  UNIFEX_TERM res_term = write_data_result_ok(env, &res_payload);
  unifex_payload_release(&res_payload);
  return res_term;
}

UNIFEX_TERM handle_data(UnifexEnv *env, State *state, UnifexPayload *payload) {
  (void)env;

  if (payload->size != 0) {
    DEBUG("Feeding: %d", payload->size);

    int bytes =
        BIO_write(SSL_get_rbio(state->ssl), payload->data, payload->size);
    if (bytes <= 0) {
      DEBUG("RBIO: write error");
      return unifex_raise(state->env, "Handshake failed: read BIO error");
    }

    DEBUG("RBIO: wrote %d", bytes);
  }

  char data[1500] = {0};
  int ret = SSL_read(state->ssl, &data, 1500);

  if (state->hsk_finished == 1) {
    return handle_regular_read(state, data, ret);
  } else if (SSL_is_init_finished(state->ssl) == 1) {
    DEBUG("Handshake finished successfully");
    return handle_handshake_finished(state);
  } else {
    DEBUG("Handshake in progress");
    return handle_handshake_in_progress(state, ret);
  }
}

UNIFEX_TERM handle_regular_read(State *state, char data[], int ret) {
  if (ret > 0) {
    UnifexPayload packets;
    unifex_payload_alloc(state->env, UNIFEX_PAYLOAD_BINARY, ret, &packets);
    memcpy(packets.data, data, ret);
    packets.size = (unsigned int)ret;
    UNIFEX_TERM res_term = handle_data_result_ok(state->env, &packets);
    unifex_payload_release(&packets);
    return res_term;
  }

  return handle_read_error(state, ret);
}

UNIFEX_TERM handle_read_error(State *state, int ret) {
  // handle READ errors including DTLS alerts
  int error = SSL_get_error(state->ssl, ret);
  switch (error) {
  case SSL_ERROR_ZERO_RETURN:
    return handle_data_result_error_peer_closed_for_writing(state->env);
  case SSL_ERROR_WANT_READ:
    DEBUG("SSL WANT READ. This is workaround. Did we get retransmission?");
    return handle_data_result_handshake_want_read(state->env);
  default:
    DEBUG("SSL ERROR. Code: %d, desc: %s", error,
          ERR_reason_error_string(ERR_get_error()));
    if (state->hsk_finished == 0) {
      // If handshake is in-progress, return handshake error.
      // Otherwise, we failed when trying to decrypt data.
      return handle_data_result_error_handshake_error(state->env);
    } else {
      return unifex_raise(state->env, "SSL read error");
    }
  }
}

UNIFEX_TERM handle_handshake_finished(State *state) {
  UNIFEX_TERM res_term;
  UnifexPayload gen_packets;
  KeyingMaterial *keying_material = export_keying_material(state->ssl);
  if (keying_material == NULL) {
    DEBUG("Cannot export keying material");
    return unifex_raise(state->env,
                        "Handshake failed: cannot export keying material");
  }

  int len = keying_material->len;
  UnifexPayload client_keying_material;
  unifex_payload_alloc(state->env, UNIFEX_PAYLOAD_BINARY, len,
                       &client_keying_material);
  memcpy(client_keying_material.data, keying_material->client, len);
  client_keying_material.size = len;

  UnifexPayload server_keying_material;
  unifex_payload_alloc(state->env, UNIFEX_PAYLOAD_BINARY, len,
                       &server_keying_material);
  memcpy(server_keying_material.data, keying_material->server, len);
  server_keying_material.size = len;

  size_t pending_data_len = BIO_ctrl_pending(SSL_get_wbio(state->ssl));
  DEBUG("WBIO: pending data: %ld bytes", pending_data_len);

  unifex_payload_alloc(state->env, UNIFEX_PAYLOAD_BINARY, pending_data_len,
                       &gen_packets);
  if (pending_data_len > 0) {
    if (read_pending_data(&gen_packets, pending_data_len, state) < 0) {
      res_term = unifex_raise(state->env, "Handshake failed: write BIO error");
      goto cleanup;
    }
  }
  state->hsk_finished = 1;

  UnifexPayload *local_keying_material;
  UnifexPayload *remote_keying_material;

  if (state->mode == MODE_CLIENT) {
    local_keying_material = &client_keying_material;
    remote_keying_material = &server_keying_material;
  } else {
    local_keying_material = &server_keying_material;
    remote_keying_material = &client_keying_material;
  }

  res_term = handle_data_result_handshake_finished(
      state->env, local_keying_material, remote_keying_material,
      keying_material->protection_profile, &gen_packets);

cleanup:
  unifex_payload_release(&gen_packets);
  unifex_payload_release(&client_keying_material);
  unifex_payload_release(&server_keying_material);
  return res_term;
}

UNIFEX_TERM handle_handshake_in_progress(State *state, int ret) {
  int ssl_error = SSL_get_error(state->ssl, ret);
  switch (ssl_error) {
  case SSL_ERROR_WANT_READ:
    DEBUG("SSL WANT READ");
    size_t pending_data_len = BIO_ctrl_pending(SSL_get_wbio(state->ssl));
    DEBUG("WBIO: pending data: %ld bytes", pending_data_len);

    if (pending_data_len > 0) {
      UnifexPayload gen_packets;
      unifex_payload_alloc(state->env, UNIFEX_PAYLOAD_BINARY, pending_data_len,
                           &gen_packets);
      if (read_pending_data(&gen_packets, pending_data_len, state) < 0) {
        return unifex_raise(state->env, "Handshake failed: write BIO error");
      }
      int timeout = get_timeout(state->ssl);
      UNIFEX_TERM res_term = handle_data_result_handshake_packets(
          state->env, &gen_packets, timeout);
      unifex_payload_release(&gen_packets);
      return res_term;
    } else {
      return handle_data_result_handshake_want_read(state->env);
    }
  default:
    return handle_read_error(state, ret);
  }
}

UNIFEX_TERM handle_timeout(UnifexEnv *env, State *state) {
  long result = DTLSv1_handle_timeout(state->ssl);
  if (result != 1)
    return handle_timeout_result_ok(env);

  BIO *wbio = SSL_get_wbio(state->ssl);
  size_t pending_data_len = BIO_ctrl_pending(wbio);
  UnifexPayload gen_packets;
  unifex_payload_alloc(env, UNIFEX_PAYLOAD_BINARY, pending_data_len,
                       &gen_packets);

  if (read_pending_data(&gen_packets, pending_data_len, state) < 0) {
    return unifex_raise(state->env,
                        "Retransmit handshake failed: write BIO error");
  } else {
    int timeout = get_timeout(state->ssl);
    UNIFEX_TERM res_term =
        handle_timeout_result_retransmit(env, &gen_packets, timeout);
    unifex_payload_release(&gen_packets);
    return res_term;
  }
}

static void ssl_info_cb(const SSL *ssl, int where, int ret) {
  UNIFEX_UNUSED(ssl);
  UNIFEX_MAYBE_UNUSED(ret);

  if (where & SSL_CB_ALERT) {
    const char *type = SSL_alert_type_string(ret);
    const char *type_long = SSL_alert_type_string_long(ret);
    const char *desc = SSL_alert_desc_string(ret);
    const char *desc_long = SSL_alert_desc_string_long(ret);

    UNIFEX_MAYBE_UNUSED(type);
    UNIFEX_MAYBE_UNUSED(type_long);
    UNIFEX_MAYBE_UNUSED(desc);
    UNIFEX_MAYBE_UNUSED(desc_long);

    DEBUG("DTLS alert occurred, where: %d, ret: %d, type: %s, type_long: %s, "
          "desc: %s, desc_long: %s",
          where, ret, type, type_long, desc, desc_long);
  }
}

static int verify_cb(int preverify_ok, X509_STORE_CTX *ctx) {
  int err = X509_STORE_CTX_get_error(ctx);

  if (err == X509_V_ERR_CERT_HAS_EXPIRED) {
    // decline expired certs
    return 0;
  } else if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
    // accept self-signed certs
    return 1;
  } else {
    return preverify_ok;
  }
}

static int read_pending_data(UnifexPayload *gen_packets, int pending_data_len,
                             State *state) {
  char *pending_data = (char *)malloc(pending_data_len * sizeof(char));
  memset(pending_data, 0, pending_data_len);
  BIO *wbio = SSL_get_wbio(state->ssl);
  int read_bytes = BIO_read(wbio, pending_data, pending_data_len);
  if (read_bytes <= 0) {
    DEBUG("WBIO: read error");
  } else {
    DEBUG("WBIO: read: %d bytes", read_bytes);
    memcpy(gen_packets->data, pending_data, pending_data_len);
    gen_packets->size = (unsigned int)pending_data_len;
  }
  free(pending_data);

  return read_bytes;
}

static void cert_to_payload(UnifexEnv *env, X509 *x509,
                            UnifexPayload *payload) {
  int len = i2d_X509(x509, NULL);
  unifex_payload_alloc(env, UNIFEX_PAYLOAD_BINARY, len, payload);
  unsigned char *p = payload->data;
  i2d_X509(x509, &p);
  payload->size = len;
}

static void pkey_to_payload(UnifexEnv *env, EVP_PKEY *pkey,
                            UnifexPayload *payload) {
  int len = i2d_PrivateKey(pkey, NULL);
  unifex_payload_alloc(env, UNIFEX_PAYLOAD_BINARY, len, payload);
  unsigned char *p = payload->data;
  i2d_PrivateKey(pkey, &p);
  payload->size = len;
}

void handle_destroy_state(UnifexEnv *env, State *state) {
  UNIFEX_UNUSED(env);
  DEBUG("Destroying state");

  if (state->ssl_ctx != NULL) {
    DEBUG("Freeing SSL_CTX");
    SSL_CTX_free(state->ssl_ctx);
  }

  if (state->ssl != NULL) {
    DEBUG("Freeing SSL");
    SSL_free(state->ssl);
  }

  if (state->x509 != NULL) {
    DEBUG("Freeing X509");
    X509_free(state->x509);
  }

  if (state->pkey != NULL) {
    DEBUG("Freeing PKEY");
    EVP_PKEY_free(state->pkey);
  }
}
