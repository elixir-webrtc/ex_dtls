#include "exit_guard.h"
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdlib.h>

// The VM stops normal schedulers before it exits, but dirty schedulers keep
// running NIFs while `exit()` runs atexit handlers. One of them is OpenSSL's
// cleanup, which frees state that a key generation in flight still uses.
// Handlers run in reverse order, so ours, registered after OpenSSL's, runs
// first. It waits for guarded calls to finish and blocks new ones.

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t no_calls = PTHREAD_COND_INITIALIZER;
static int calls = 0;
static int exiting = 0;

static void wait_for_calls(void) {
  pthread_mutex_lock(&lock);
  exiting = 1;
  while (calls > 0) {
    pthread_cond_wait(&no_calls, &lock);
  }
  pthread_mutex_unlock(&lock);
}

int exit_guard_init(void) {
  // registers OpenSSL's atexit handler, unless another library already did
  if (!OPENSSL_init_ssl(0, NULL)) {
    return -1;
  }

  return atexit(wait_for_calls);
}

void exit_guard_enter(void) {
  pthread_mutex_lock(&lock);
  // once the VM is exiting, block until the process is gone
  while (exiting) {
    pthread_cond_wait(&no_calls, &lock);
  }
  calls++;
  pthread_mutex_unlock(&lock);
}

void exit_guard_leave(void) {
  pthread_mutex_lock(&lock);
  calls--;
  if (calls == 0) {
    pthread_cond_broadcast(&no_calls);
  }
  pthread_mutex_unlock(&lock);
}
