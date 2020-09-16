#pragma once

#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define HANDSHAKE_STATE_READY 110
#define HANDSHAKE_STATE_STARTED 111
#define HANDSHAKE_STATE_FINISHED 112

SSL_CTX *create_ctx(void);
SSL *create_ssl(SSL_CTX *ssl_ctx, int client_mode);
unsigned char *export_keying_material(SSL *ssl);
