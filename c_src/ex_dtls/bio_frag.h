#include <openssl/opensslv.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "log.h"

const BIO_METHOD *BIO_f_frag(void);