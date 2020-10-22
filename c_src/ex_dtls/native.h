#pragma once

#include "dtls.h"
#include <unifex/unifex.h>

typedef struct State State;

struct State {
  UnifexEnv *env;
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  int SSL_error;
  EVP_PKEY *pkey;
  X509 *x509;
  int client_mode;
};

#include "_generated/native.h"
