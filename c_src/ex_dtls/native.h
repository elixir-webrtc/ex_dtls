#pragma once

#include "dtls.h"
#include <unifex/unifex.h>

typedef struct State State;

struct State {
  UnifexEnv *env;
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  EVP_PKEY *pkey;
  X509 *x509;
  int mode;
  int hsk_finished;
  int closed;
};

#include "_generated/native.h"
