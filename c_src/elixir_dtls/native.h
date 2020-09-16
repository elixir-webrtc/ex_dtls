#pragma once

#include <unifex/unifex.h>
#include "dtls.h"

typedef struct State State;

struct State {
  UnifexEnv *env;
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  int handshake_state;
  int client_mode;
  pthread_t rx_fun_tid;
  pthread_t tx_fun_tid;
  pthread_t handshake_fun_tid;
  pthread_t listen_fun_tid;
  int socket_fd;
  int peer_fd;
};

#include "_generated/native.h"
