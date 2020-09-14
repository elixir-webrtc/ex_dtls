#pragma once

#include <openssl/ssl.h>
#include "unifex/unifex.h"

#define HANDSHAKE_STATE_STARTED 110
#define HANDSHAKE_STATE_FINISHED 111

typedef struct State State;

struct State {
  UnifexEnv *env;
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  int handshake_state;
  pthread_t sending_fun_tid;
  pthread_t handshake_fun_tid;
};


SSL_CTX *create_ctx(void);
SSL *create_ssl(SSL_CTX *ssl_ctx);

#include "_generated/native.h"
