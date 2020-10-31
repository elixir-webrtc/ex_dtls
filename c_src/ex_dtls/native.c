#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "dyn_buff.h"
#include "native.h"

#define BUF_LEN 2048

#define DEBUG(X, ...)                                                          \
  printf(X "\n", ##__VA_ARGS__);                                               \
  fflush(stdout);

UNIFEX_TERM init(UnifexEnv *env, int client_mode, int dtls_srtp) {
  UNIFEX_TERM res_term;
  State *state = unifex_alloc_state(env);
  state->env = env;

  state->ssl_ctx = create_ctx(dtls_srtp);
  if (state->ssl_ctx == NULL) {
    res_term = unifex_raise(env, "Cannot create ssl_ctx");
    goto exit;
  }

  state->pkey = gen_key();
  if (state->pkey == NULL) {
    res_term = unifex_raise(env, "Cannot generate key pair");
    goto exit;
}

  if (SSL_CTX_use_PrivateKey(state->ssl_ctx, state->pkey) != 1) {
    res_term = unifex_raise(env, "Cannot set private key");
    goto exit;
  }

  state->x509 = gen_cert(state->pkey);
  if (state->x509 == NULL) {
    res_term = unifex_raise(env, "Cannot generate cert");
    goto exit;
}

  if (SSL_CTX_use_certificate(state->ssl_ctx, state->x509) != 1) {
    res_term = unifex_raise(env, "Cannot set cert");
    goto exit;
  }

  state->ssl = create_ssl(state->ssl_ctx, client_mode);
  if (state->ssl == NULL) {
    res_term = unifex_raise(env, "Cannot create ssl");
    goto exit;
  }

  state->client_mode = client_mode;
  state->SSL_error = SSL_ERROR_NONE;
  res_term = init_result_ok(env, state);

exit:
  unifex_release_state(env, state);
  return res_term;
}

UNIFEX_TERM get_cert_fingerprint(UnifexEnv *env, State *state) {
  unsigned char md[EVP_MAX_MD_SIZE] = {0};
  unsigned int size;
  if (X509_digest(state->x509, EVP_sha256(), md, &size) != 1) {
    return unifex_raise(env, "Can't get cert fingerprint");
  }
  UnifexPayload *payload = (UnifexPayload *)unifex_payload_alloc(
            env, UNIFEX_PAYLOAD_BINARY, size);
  memcpy(payload->data, md, size);
  payload->size = size;
  UNIFEX_TERM res_term = get_cert_fingerprint_result_ok(env, state, payload);
  unifex_payload_release(payload);
  return res_term;
}

UNIFEX_TERM do_handshake(UnifexEnv *env, State *state, UnifexPayload *payload) {
  DynBuff *dyn_buff = dyn_buff_new(1024);
  if (dyn_buff == NULL) {
    return unifex_raise(env, "Handshake failed: can't create new dyn_buff");
  }

  if (payload->size != 0) {
    DEBUG("Feeding: %d", payload->size);

    int bytes = BIO_write(SSL_get_rbio(state->ssl), payload->data, payload->size);
    if (bytes <= 0) {
      DEBUG("RBIO: write error");
      return unifex_raise(state->env, "Handshake failed: read BIO error");
    }

    DEBUG("RBIO: wrote %d", bytes);
  }

  for (;;) {
    int res = SSL_do_handshake(state->ssl);

    size_t pending_data_len = BIO_ctrl_pending(SSL_get_wbio(state->ssl));
    if (pending_data_len > 0) {
      DEBUG("WBIO: pending data: %ld bytes", pending_data_len);

      char *data = (char *)malloc(pending_data_len * sizeof(char));
      memset(data, 0, pending_data_len);
      BIO *wbio = SSL_get_wbio(state->ssl);
      int read_bytes = BIO_read(wbio, data, pending_data_len);
      if (read_bytes <= 0) {
        DEBUG("WBIO: read error");
        return unifex_raise(state->env, "Handshake failed: write BIO error");
      } else {
        if (dyn_buff_insert(dyn_buff, data, read_bytes) == -1) {
           return unifex_raise(state->env, "Handshake failed: can't insert to dyn_buff");
        }
      }

      DEBUG("WBIO: read: %d bytes", read_bytes);

      free(data);
    }

    res = SSL_get_error(state->ssl, res);
    switch (res) {
    case SSL_ERROR_WANT_READ:
      DEBUG("SSL WANT READ");
      state->SSL_error = SSL_ERROR_WANT_READ;
      // break and wait for data from remote host. It will come in feed()
      // function.
      UnifexPayload *payload = (UnifexPayload *)unifex_payload_alloc(
          env, UNIFEX_PAYLOAD_BINARY, dyn_buff->data_size);
      memcpy(payload->data, dyn_buff->data, dyn_buff->data_size);
      payload->size = (unsigned int)dyn_buff->data_size;
      UNIFEX_TERM res_term = do_handshake_result_ok(env, state, payload);
      dyn_buff_free(dyn_buff);
      unifex_payload_release(payload);
      return res_term;
    case SSL_ERROR_WANT_WRITE:
      DEBUG("SSL WANT WRITE");
      break;
    case SSL_ERROR_NONE:
      /*
        This will be reached only when handshake succeeds because SSL_ERROR_NONE
        is returned only when res (passed to SSL_get_error) is greater than 0
        and res greater than zero means handshake succeeded.
      */
      DEBUG("Handshake finished successfully");

      KeyingMaterial *keying_material = export_keying_material(state->ssl);
      if (keying_material == NULL) {
        DEBUG("Cannot export keying material");
        exit(EXIT_FAILURE);
      }

      int len = keying_material->len;
      UnifexPayload *client_keying_material =
          (UnifexPayload *)unifex_payload_alloc(env, UNIFEX_PAYLOAD_BINARY, len);
      memcpy(client_keying_material->data, keying_material->client, len);
      client_keying_material->size = len;

      UnifexPayload *server_keying_material =
          (UnifexPayload *)unifex_payload_alloc(env, UNIFEX_PAYLOAD_BINARY, len);
      memcpy(server_keying_material->data, keying_material->server, len);
      server_keying_material->size = len;

      if (dyn_buff->data_size == 0) {
        UNIFEX_TERM res_term = do_handshake_result_finished(
            env, state, client_keying_material, server_keying_material,
            keying_material->protection_profile);
        dyn_buff_free(dyn_buff);
        unifex_payload_release(client_keying_material);
        unifex_payload_release(server_keying_material);
        return res_term;
      } else {
        UnifexPayload *payload = (UnifexPayload *)unifex_payload_alloc(
            env, UNIFEX_PAYLOAD_BINARY, dyn_buff->data_size);
        memcpy(payload->data, dyn_buff->data, dyn_buff->data_size);
        payload->size = (unsigned int)dyn_buff->data_size;
        UNIFEX_TERM res_term = do_handshake_result_finished_with_packets(
            env, state, client_keying_material, server_keying_material,
            keying_material->protection_profile, payload);
        dyn_buff_free(dyn_buff);
        unifex_payload_release(payload);
        unifex_payload_release(client_keying_material);
        unifex_payload_release(server_keying_material);
        return res_term;
      }
    default:
      DEBUG("SSL ERROR: %d", res);
      return unifex_raise(state->env, "Handshake failed: SSL error");
    }
  }
}

void handle_destroy_state(UnifexEnv *env, State *state) {
  UNIFEX_UNUSED(env);
  DEBUG("Destroying state");

  if (state->ssl_ctx) {
    SSL_CTX_free(state->ssl_ctx);
  }

  if (state->ssl) {
    SSL_free(state->ssl);
  }

  if (state->pkey) {
    EVP_PKEY_free(state->pkey);
  }

  if (state->x509) {
    X509_free(state->x509);
  }
}
