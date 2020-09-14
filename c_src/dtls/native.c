#include <stdio.h>

#include "native.h"

SSL_CTX *create_ctx() {
  SSL_CTX *ssl_ctx = SSL_CTX_new(DTLS_method());
  int res = SSL_CTX_set_tlsext_use_srtp(ssl_ctx, "SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32:SRTP_AEAD_AES_128_GCM:SRTP_AEAD_AES_256_GCM");
  if (res != 0) {
    perror("Cannot set SRTP extension\n");
    exit(EXIT_FAILURE);
  }
  if (ssl_ctx == NULL) {
    perror("Cannot create SSL context");
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_use_certificate_file(ssl_ctx, "./cert.pem", SSL_FILETYPE_PEM) != 1) {
    perror("Cannot load certificate file");
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "./key.pem", SSL_FILETYPE_PEM) != 1) {
    perror("Cannot load key file");
    exit(EXIT_FAILURE);
  }

  return ssl_ctx;
}

SSL *create_ssl(SSL_CTX *ssl_ctx) {
  SSL *ssl = SSL_new(ssl_ctx);
  SSL_set_connect_state(ssl);
  if (ssl == NULL) {
    perror("Cannot create ssl structure");
    exit(EXIT_FAILURE);
  }

  BIO *rbio = BIO_new(BIO_s_mem());
  if (rbio == NULL) {
    perror("Cannot create rbio");
    exit(EXIT_FAILURE);
  }

  BIO *wbio = BIO_new(BIO_s_mem());
  if (wbio == NULL) {
    perror("Cannot create wbio");
    exit(EXIT_FAILURE);
  }

  SSL_set_bio(ssl, rbio, wbio);

  return ssl;
}

UNIFEX_TERM do_handshake(UnifexEnv *env, State *state) {
  State *state = unifex_alloc_state(env);
  state->env = env;
  state->ssl_ctx = create_ctx();
  state->ssl = create_ssl(state->ssl_ctx);

  state->handshake_state = HANDSHAKE_STATE_STARTED;
  if (pthread_create(&state->sending_fun_tid, NULL, sending_function, (void *) state)) {
      perror("Cannot create sending function thread");
      exit(EXIT_FAILURE);
  }
  if (pthread_create(&state->handshake_fun_tid, NULL, handshake_function, (void *) state)) {
    perror("Cannot create handshake function thread");
    exit(EXIT_FAILURE);
  }
  return do_handshake_result_ok(env);
}

static void *handshake_function(void *user_data) {
  State *state = (State *)user_data;
  while(1) {
    int res = SSL_do_handshake(state->ssl);
    if(res != 1) {
        res = SSL_get_error(state->ssl, res);
        if(res != SSL_ERROR_WANT_READ){
          ERR_print_errors_fp(stderr);
          printf("SSL_do_handshake error: %d\n", res);
          fflush(stdout);
          exit(EXIT_FAILURE);
        }
    } else {
      break;
    }
  }
  if (SSL_is_init_finished(state->ssl)) {
    state->handshake_state = HANDSHAKE_STATE_FINISHED;
    char *material = export_keying_material(state);
    send_handshake_finished(state->env, *state->env->reply_to, 0, material);
    printf("handshake successful\n");
    fflush(stdout);
  }
  printf("handshake finished\n");
  fflush(stdout);
  return NULL;
}

static char *export_keying_material(State *state) {
  SRTP_PROTECTION_PROFILE *srtp_profile = SSL_get_selected_srtp_profile(state->ssl);
  int master_key_len;
  int master_salt_len;
  switch(srtp_profile->id) {
    case SRTP_AES128_CM_SHA1_80:
      master_key_len = 16;
      master_salt_len = 14;
      break;
    case SRTP_AES128_CM_SHA1_32:
      master_key_len = 16;
      master_salt_len = 14;
      break;
    case SRTP_AEAD_AES_128_GCM:
      master_key_len = 16;
      master_salt_len = 12;
      break;
    case SRTP_AEAD_AES_256_GCM:
      master_key_len = 32;
      master_salt_len = 12;
      break;
    default:
      printf("Unsupported SRTP protection profile\n");
      fflush(stdout);
      exit(EXIT_FAILURE);
  }

  int len = 2 * (master_key_len + master_salt_len);
  char *material = (char *) malloc(len * sizeof(char));
  memset(material, 0, len);
  int res = SSL_export_keying_material(state->ssl, material, len, "EXTRACTOR-dtls_srtp", 19, NULL, 0, 0);
  if (res != 1) {
    printf("Cannot export keying material\n");
    fflush(stdout);
    exit(EXIT_FAILURE);
  } else {
    printf("Keying material: %s\n", material);
    fflush(stdout);
  }
  return material;
}

static void *sending_function(void *user_data) {
  State *state = (State *) user_data;
  while (state->handshake_state != HANDSHAKE_STATE_FINISHED) {
    size_t pending_data_len = BIO_ctrl_pending(SSL_get_wbio(state->ssl));
    if (pending_data_len > 0) {
      char *data = (char *) malloc(pending_data_len * sizeof(char));
      if (BIO_read(SSL_get_wbio(state->ssl), data, pending_data_len) != (int) pending_data_len) {
        perror("Read error");
        exit(EXIT_FAILURE);
      }
      int bytes = nice_agent_send(state->agent, 1, 1, pending_data_len, data);
      printf("sent %d bytes\n", bytes);
      fflush(stdout);
      free(data);
    }
  }
}
