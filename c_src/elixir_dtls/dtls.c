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

  EVP_PKEY *pkey = gen_key();
  SSL_CTX_use_PrivateKey(ssl_ctx, pkey);

  X509 *x509 = gen_cert(pkey);
  SSL_CTX_use_certificate(ssl_ctx, x509);

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
  }
  return material;
}

EVP_PKEY *gen_key() {
  EVP_PKEY *pkey;
  pkey = EVP_PKEY_new();

  RSA *rsa = RSA_new();
  BIGNUM *exp = BN_new();
  BN_set_word(exp, 65537L);
  RSA_generate_key_ex(rsa, 2048, exp, NULL);
  if (rsa == NULL) {
    printf("error\n");
    fflush(stdout);
  }
  EVP_PKEY_assign_RSA(pkey, rsa);

  return pkey;
}

X509 *gen_cert(EVP_PKEY *pkey) {
  X509 *x509;
  x509 = X509_new();
  ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

  X509_gmtime_adj(X509_get_notBefore(x509), 0);
  X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

  X509_set_pubkey(x509, pkey);

  X509_NAME * name;
  name = X509_get_subject_name(x509);

  X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC,
                             (unsigned char *)"PL", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC,
                             (unsigned char *)"MyCompany Inc.", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                             (unsigned char *)"localhost", -1, -1, 0);

  X509_set_issuer_name(x509, name);
  X509_sign(x509, pkey, EVP_sha1());

  return x509;
}
