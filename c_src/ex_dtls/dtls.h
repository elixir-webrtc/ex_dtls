#pragma once

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <string.h>
#include <sys/time.h>

#include "log.h"

#define MODE_CLIENT 0
#define MODE_SERVER 1

typedef struct KeyingMaterial {
  unsigned char *client; // client keying material - master key + master salt
  unsigned char *server;
  unsigned int len; // len of client/server keying material
  int protection_profile;
} KeyingMaterial;

SSL_CTX *create_ctx(int dtls_srtp);
SSL *create_ssl(SSL_CTX *ssl_ctx, int mode);
KeyingMaterial *export_keying_material(SSL *ssl);
EVP_PKEY *gen_key();
X509 *gen_cert(EVP_PKEY *pkey, long not_before, long not_after);
EVP_PKEY *decode_pkey(unsigned char *buf, int len);
X509 *decode_cert(unsigned char *buf, int len);
int get_timeout(SSL *ssl);
