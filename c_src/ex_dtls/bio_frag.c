
#include "bio_frag.h"

static int bwrite(BIO *bio, const char *buf, int len);
static int bread(BIO *bio, char *buf, int len);
static long ctrl(BIO *bio, int cmd, long arg1, void *arg2);
static int create(BIO *bio);
static int destroy(BIO *bio);
static long callback_ctrl(BIO *bio, int cmd, BIO_info_cb *fp);

// static const BIO_METHOD bio_methods = {
//   BIO_TYPE_BIO,
//   "DTLS fragmentation for mem BIO",
//   bwrite_conv,
//   bwrite,
//   bread_conv,
//   bread,
//   NULL,
//   NULL,
//   ctrl,
//   create,
//   destroy,
//   callback_ctrl
// };

static BIO_METHOD *bio_methods = NULL;

const BIO_METHOD *BIO_f_frag(void) {
  bio_methods = BIO_meth_new(BIO_TYPE_FILTER, "DTLS fragmentation for mem BIO");

  BIO_meth_set_read(bio_methods, bread);
  BIO_meth_set_write(bio_methods, bwrite);
  BIO_meth_set_ctrl(bio_methods, ctrl);
  BIO_meth_set_create(bio_methods, create);
  BIO_meth_set_destroy(bio_methods, destroy);
  BIO_meth_set_callback_ctrl(bio_methods, callback_ctrl);

  return bio_methods;
}

static int create(BIO *bio) {
  DEBUG("BIO frag create");
  // indicate that BIO initialization is complete 
  BIO_set_init(bio, 1);
  return 1;
}

static int destroy(BIO *bio) {
  DEBUG("BIO frag destroy");
  if (bio == NULL) {
    return 0;
  }

  BIO_set_init(bio, 0);
  return 1;
}

static int bread(BIO *bio, char *buf, int len) {
  DEBUG("BIO frag bread");
  BIO *next = BIO_next(bio);
  if (next == NULL) {
    return 0;
  }

  return BIO_read(next, buf, len);
}

static int bwrite(BIO *bio, const char *buf, int len) {
  DEBUG("BIO frag bwrite %d", len);
  BIO *next = BIO_next(bio);
  if (next == NULL) {
    return 0;
  }

  return BIO_write(next, buf, len);
}

static long ctrl(BIO *bio, int cmd, long num, void *ptr) {
  DEBUG("BIO frag ctrl");

  BIO *next = BIO_next(bio);
  if (next == NULL) {
    return 0;
  }

  return BIO_ctrl(next, cmd, num, ptr);
}

static long callback_ctrl(BIO *bio, int cmd, BIO_info_cb *fp) {
  BIO *next = BIO_next(bio);
  if (next == NULL) {
    return 0;
  }

  return BIO_callback_ctrl(next, cmd, fp);
}


