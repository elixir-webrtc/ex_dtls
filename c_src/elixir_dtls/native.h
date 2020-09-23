#pragma once

#include <unifex/unifex.h>
#include "dtls.h"

typedef struct State State;

struct State {
  UnifexEnv *env;
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  EVP_PKEY *pkey;
  X509 *x509;
  int client_mode;
  pthread_t handshake_fun_tid;
  pthread_t listen_fun_tid;
  int socket_fd;
  int peer_fd;
};

#include "_generated/native.h"
