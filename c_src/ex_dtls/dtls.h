#pragma once

#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>

SSL_CTX *create_ctx(int dtls_srtp);
SSL *create_ssl(SSL_CTX *ssl_ctx, int client_mode);
unsigned char *export_keying_material(SSL *ssl);
EVP_PKEY *gen_key();
X509 *gen_cert(EVP_PKEY *pkey);