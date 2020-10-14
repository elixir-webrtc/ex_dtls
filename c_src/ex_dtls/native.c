#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "native.h"
#include "dyn_buff.h"

#define BUF_LEN 2048

#define DEBUG(X, ...)                                                          \
  printf(X "\n", ##__VA_ARGS__);                                               \
  fflush(stdout);

UNIFEX_TERM init(UnifexEnv *env, int client_mode, int dtls_srtp) {
  State *state = unifex_alloc_state(env);
  state->env = env;

  state->ssl_ctx = create_ctx(dtls_srtp);
  if (state->ssl_ctx == NULL) {
    return unifex_raise(env, "Cannot create ssl_ctx");
  }

  state->pkey = gen_key();
  if (state->pkey == NULL) {
    return unifex_raise(env, "Cannot generate key pair");
  }

  if (SSL_CTX_use_PrivateKey(state->ssl_ctx, state->pkey) != 1) {
    return unifex_raise(env, "Cannot set private key");
  }

  state->x509 = gen_cert(state->pkey);
  if (state->x509 == NULL) {
    return unifex_raise(env, "Cannot generate cert");
  }

  if (SSL_CTX_use_certificate(state->ssl_ctx, state->x509) != 1) {
    return unifex_raise(env, "Cannot set cert");
  }

  state->ssl = create_ssl(state->ssl_ctx, client_mode);
  if (state->ssl == NULL) {
    return unifex_raise(env, "Cannot create ssl");
  }

  state->client_mode = client_mode;
  state->SSL_error = SSL_ERROR_NONE;

  return init_result_ok(env, state);
}

UNIFEX_TERM get_cert_fingerprint(UnifexEnv *env, State *state) {
  unsigned char md[EVP_MAX_MD_SIZE] = {0};
  unsigned int size;
  if(X509_digest(state->x509, EVP_sha256(), md, &size) != 1) {
    get_cert_fingerprint_result_error_failed_to_get_fingerprint(env);
  }
  return get_cert_fingerprint_result_ok(env, state, (char *)md);
}

UNIFEX_TERM do_handshake(UnifexEnv *env, State *state, UnifexPayload *payload) {
  DynBuff *dyn_buff = dyn_buff_new(1024);

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
        dyn_buff_insert(dyn_buff, data, read_bytes);
      }

      DEBUG("WBIO: read: %d bytes", read_bytes);

      free(data);
    }

    res = SSL_get_error(state->ssl, res);
    switch (res) {
    case SSL_ERROR_WANT_READ:
      DEBUG("SSL WANT READ");
      state->SSL_error = SSL_ERROR_WANT_READ;
      // break and wait for data from remote host. It will come in feed() function.
      UnifexPayload *payload = (UnifexPayload *)unifex_payload_alloc(env, UNIFEX_PAYLOAD_BINARY, dyn_buff->data_size);
      memcpy(payload->data, dyn_buff->data, dyn_buff->data_size);
      payload->size = (unsigned int)dyn_buff->data_size;
      dyn_buff_free(dyn_buff);
      return do_handshake_result_ok(env, state, payload);
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

      unsigned char *material = export_keying_material(state->ssl);
      if (material == NULL) {
        DEBUG("Cannot export keying material");
        exit(EXIT_FAILURE);
      }

      DEBUG("Keying material %s", material);
      if (dyn_buff->data_size == 0) {
        dyn_buff_free(dyn_buff);
        return do_handshake_result_finished(env, state, (char *)material);
      } else {
        UnifexPayload *payload = (UnifexPayload *)unifex_payload_alloc(env, UNIFEX_PAYLOAD_BINARY, dyn_buff->data_size);
        memcpy(payload->data, dyn_buff->data, dyn_buff->data_size);
        payload->size = (unsigned int)dyn_buff->data_size;
        dyn_buff_free(dyn_buff);
        return do_handshake_result_finished_with_packets(env, state, (char *)material, payload);
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
