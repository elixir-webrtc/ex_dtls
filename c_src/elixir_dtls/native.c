#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "native.h"
#include "dtls.h"

static int init_socket(char *path);
static void run_listen_thread(State *state);
static void *listen_function(void *user_data);
static void *handshake_function(void *user_data);

#define BUF_LEN 2048

#define DEBUG(X, ...) printf(X "\n", ##__VA_ARGS__ ); \
                      fflush(stdout);                 \

UNIFEX_TERM init(UnifexEnv *env, char *socket_path, int client_mode) {
  State *state = unifex_alloc_state(env);
  state->env = env;
  state->ssl_ctx = create_ctx();
  state->ssl = create_ssl(state->ssl_ctx, client_mode);
  state->socket_fd = init_socket(socket_path);
  state->client_mode = client_mode;

  run_listen_thread(state);

  return init_result_ok(env, state);
}

static int init_socket(char *socket_path) {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, socket_path);

  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
    perror("bind");
    exit(EXIT_FAILURE);
  }

  return fd;
}

static void run_listen_thread(State *state) {
  if (pthread_create(&state->listen_fun_tid, NULL, listen_function, (void *)state)) {
    perror("Cannot create listen function thread");
    exit(EXIT_FAILURE);
  }
}

static void *listen_function(void *user_data) {
  State *state = (State *)user_data;
  if(listen(state->socket_fd, 1) == -1) {
    perror("Listen error");
    exit(EXIT_FAILURE);
  }

  int peer_fd = accept(state->socket_fd, NULL, NULL);
  if(peer_fd == -1) {
    perror("Accept error");
    exit(EXIT_FAILURE);
  }
  state->peer_fd = peer_fd;

  DEBUG("DTLS MODULE READY");

  return NULL;
}

UNIFEX_TERM do_handshake(UnifexEnv *env, State *state) {
  state->handshake_state = HANDSHAKE_STATE_STARTED;
  if (pthread_create(&state->handshake_fun_tid, NULL, handshake_function, (void *) state)) {
    perror("Cannot create handshake function thread");
    exit(EXIT_FAILURE);
  }
  return do_handshake_result_ok(env, state);
}

static void *handshake_function(void *user_data) {
  State *state = (State *)user_data;
  while(1) {
    int res = SSL_do_handshake(state->ssl);
    size_t pending_data_len = BIO_ctrl_pending(SSL_get_wbio(state->ssl));
    if (pending_data_len > 0) {
      char *data = (char *) malloc(pending_data_len * sizeof(char));
      memset(data, 0, pending_data_len);
      int read_bytes = BIO_read(SSL_get_wbio(state->ssl), data, pending_data_len);
      if (read_bytes != (int) pending_data_len) {
        DEBUG("Read error read: %d, pending %ld", read_bytes, pending_data_len);
      }
      ssize_t bytes = send(state->peer_fd, data, pending_data_len, 0);

      DEBUG("Sent %ld bytes", bytes);

      free(data);
    }
    res = SSL_get_error(state->ssl, res);
    switch(res) {
      case SSL_ERROR_WANT_READ:
        DEBUG("SSL WANT READ");

        char buf[BUF_LEN] = {0};
        int bytes = recv(state->peer_fd, buf, BUF_LEN, 0);

        DEBUG("Recv: %d", bytes);

        if (bytes == 0) {
          DEBUG("Peer socket shutdown, handshake failed");

          send_handshake_failed_peer_shutdown(state->env, *state->env->reply_to, 0);
          exit(EXIT_FAILURE);
        }
        if (BIO_write(SSL_get_rbio(state->ssl), buf, bytes) != bytes) {
          DEBUG("BIO write error");

          ERR_print_errors_fp(stderr);
          exit(EXIT_FAILURE);
        }
        break;
      case SSL_ERROR_WANT_WRITE:
        DEBUG("SSL WANT WRITE");
        break;
      case SSL_ERROR_NONE:
        /*
          This will be reached only when handshake succeeds because SSL_ERROR_NONE is returned
          only when res (passed to SSL_get_error) is greater than 0 and res greater than zero
          means handshake succeeded.
        */
        DEBUG("Handshake finished");

        unsigned char *material = export_keying_material(state->ssl);

        DEBUG("Keying material %s", material);

        send_handshake_finished(state->env, *state->env->reply_to, 0, (char *)material);

        exit(EXIT_SUCCESS);
      default:
        DEBUG("SSL ERROR: %d", res);

        send_handshake_failed(state->env, *state->env->reply_to, 0, res);
        exit(EXIT_FAILURE);
    }
  }

  return NULL;
}

void handle_destroy_state(UnifexEnv *env, State *state) {
  UNIFEX_UNUSED(env);
  DEBUG("Destroying state");
  shutdown(state->socket_fd, SHUT_RDWR);
  close(state->socket_fd);
  free(state->ssl_ctx);
  free(state->ssl);
}
