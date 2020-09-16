#include "dtls.h"

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

  if (SSL_CTX_use_certificate_file(ssl_ctx, "/home/michal/Repos/elixir_dtls/c_src/elixir_dtls/cert.pem", SSL_FILETYPE_PEM) != 1) {
    perror("Cannot load certificate file");
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "/home/michal/Repos/elixir_dtls/c_src/elixir_dtls/key.pem", SSL_FILETYPE_PEM) != 1) {
    perror("Cannot load key file");
    exit(EXIT_FAILURE);
  }

  return ssl_ctx;
}

SSL *create_ssl(SSL_CTX *ssl_ctx, int client_mode) {
  SSL *ssl = SSL_new(ssl_ctx);

  if (client_mode) {
    SSL_set_connect_state(ssl);
  } else {
    SSL_set_accept_state(ssl);
  }

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

unsigned char *export_keying_material(SSL *ssl) {
  SRTP_PROTECTION_PROFILE *srtp_profile = SSL_get_selected_srtp_profile(ssl);
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
  unsigned char *material = (unsigned char *) malloc(len * sizeof(char));
  memset(material, 0, len);
  int res = SSL_export_keying_material(ssl, material, len, "EXTRACTOR-dtls_srtp", 19, NULL, 0, 0);
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
