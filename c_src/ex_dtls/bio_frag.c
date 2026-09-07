
#include "bio_frag.h"
#include <openssl/bio.h>
#include <openssl/crypto.h>

static int bwrite(BIO *bio, const char *buf, int len);
static int bread(BIO *bio, char *buf, int len);
static long ctrl(BIO *bio, int cmd, long arg1, void *arg2);
static int create(BIO *bio);
static int destroy(BIO *bio);
static long callback_ctrl(BIO *bio, int cmd, BIO_info_cb *fp);

static BIO_METHOD *bio_methods = NULL;
static CRYPTO_ONCE bio_methods_once = CRYPTO_ONCE_STATIC_INIT;

#define MAX_FRAGS 100
#define MTU 1200

struct Ctx {
  int frag_sizes[MAX_FRAGS];
  int witer;
  int riter;
};

// Built once: rebuilding the method per call let a concurrent caller create a
// BIO from a half-populated method (no create callback, so no Ctx) and crash.
static void init_bio_methods(void) {
  BIO_METHOD *methods =
      BIO_meth_new(BIO_TYPE_FILTER, "DTLS fragmentation for mem BIO");
  if (methods == NULL) {
    return;
  }
  BIO_meth_set_read(methods, bread);
  BIO_meth_set_write(methods, bwrite);
  BIO_meth_set_ctrl(methods, ctrl);
  BIO_meth_set_create(methods, create);
  BIO_meth_set_destroy(methods, destroy);
  BIO_meth_set_callback_ctrl(methods, callback_ctrl);
  bio_methods = methods;
}

const BIO_METHOD *BIO_f_frag(void) {
  if (!CRYPTO_THREAD_run_once(&bio_methods_once, init_bio_methods)) {
    return NULL;
  }
  return bio_methods;
}

static int create(BIO *bio) {
  struct Ctx *ctx = calloc(1, sizeof(struct Ctx));
  for (int i = 0; i < MAX_FRAGS; i++) {
    ctx->frag_sizes[i] = 0;
  }
  ctx->witer = 0;
  ctx->riter = 0;

  BIO_set_data(bio, ctx);
  BIO_set_init(bio, 1);
  return 1;
}

static int destroy(BIO *bio) {
  if (bio == NULL) {
    return 0;
  }

  struct Ctx *ctx = BIO_get_data(bio);
  free(ctx);
  BIO_set_data(bio, NULL);
  BIO_set_init(bio, 0);
  return 1;
}

static int bread(BIO *bio, char *buf, int len) {
  BIO *next = BIO_next(bio);
  if (next == NULL) {
    return 0;
  }

  struct Ctx *ctx = BIO_get_data(bio);

  if (len != ctx->frag_sizes[ctx->riter]) {
    return 0;
  }

  int ret = BIO_read(next, buf, len);

  if (ret > 0) {
    if (ret == ctx->frag_sizes[ctx->riter]) {
      ctx->frag_sizes[ctx->riter] = 0;
      ctx->riter++;

      if (ctx->riter == ctx->witer && ctx->frag_sizes[ctx->riter] == 0) {
        // reset iterators
        ctx->riter = 0;
        ctx->witer = 0;
      }

    } else if (ret < ctx->frag_sizes[ctx->riter]) {
      ctx->frag_sizes[ctx->riter] -= ret;
    } else {
      // This should never happen
      return 0;
    }
  };

  return ret;
}

static int bwrite(BIO *bio, const char *buf, int len) {
  BIO *next = BIO_next(bio);
  if (next == NULL) {
    return 0;
  }

  struct Ctx *ctx = BIO_get_data(bio);

  if (ctx->witer >= MAX_FRAGS) {
    return 0;
  }

  int ret = BIO_write(next, buf, len);
  if (ret > 0) {
    ctx->frag_sizes[ctx->witer] = ret;
    ctx->witer++;
  }

  return ret;
}

static long ctrl(BIO *bio, int cmd, long num, void *ptr) {
  BIO *next = BIO_next(bio);
  if (next == NULL) {
    return 0;
  }

  struct Ctx *ctx = BIO_get_data(bio);

  if (cmd == BIO_CTRL_PENDING) {
    return ctx->frag_sizes[ctx->riter];
  } else if (cmd == BIO_CTRL_DGRAM_QUERY_MTU) {
    return MTU;
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
