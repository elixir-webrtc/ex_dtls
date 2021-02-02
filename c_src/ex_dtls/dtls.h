#pragma once

#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <string.h>

#include "log.h"

typedef struct KeyingMaterial {
  unsigned char *client; // client keying material - master key + master salt
  unsigned char *server;
  unsigned int len; // len of client/server keying material
  int protection_profile;
} KeyingMaterial;

SSL_CTX *create_ctx(int dtls_srtp);
SSL *create_ssl(SSL_CTX *ssl_ctx, int client_mode);
KeyingMaterial *export_keying_material(SSL *ssl);
EVP_PKEY *gen_key();
X509 *gen_cert(EVP_PKEY *pkey);
