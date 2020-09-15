#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "native.h"
#include "dtls.h"

static int init_socket(void);
static void run_listen_thread(State *state);
static void *listen_function(void *user_data);
static void *sending_function(void *user_data);
static void *handshake_function(void *user_data);

UNIFEX_TERM init(UnifexEnv *env, char *socket_path) {
  State *state = unifex_alloc_state(env);
  state->env = env;
  state->ssl_ctx = create_ctx();
  state->ssl = create_ssl(state->ssl_ctx);
  state->socket_fd = init_socket(socket_path);

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

  return NULL;
}


UNIFEX_TERM do_handshake(UnifexEnv *env, State *state) {
  state->handshake_state = HANDSHAKE_STATE_STARTED;
  if (pthread_create(&state->rx_fun_tid, NULL, rx_function, (void *) state)) {
    perror("Cannot create rx function thread");
    exit(EXIT_FAILURE);
  }
  if (pthread_create(&state->tx_fun_tid, NULL, tx_function, (void *) state)) {
    perror("Cannot create tx function thread");
    exit(EXIT_FAILURE);
  }
  if (pthread_create(&state->handshake_fun_tid, NULL, handshake_function, (void *) state)) {
    perror("Cannot create handshake function thread");
    exit(EXIT_FAILURE);
  }
  return do_handshake_result_ok(env, state);
}

static void *handshake_function(void *user_data) {
  State *state = (State *)user_data;
  while(state->handshake_state != HANDSHAKE_STATE_FINISHED) {
    int res = SSL_do_handshake(state->ssl);
    if(res != 1) {
      res = SSL_get_error(state->ssl, res);
      if(res != SSL_ERROR_WANT_READ){
        ERR_print_errors_fp(stderr);
        printf("SSL_do_handshake error: %d\n", res);
        fflush(stdout);
        exit(EXIT_FAILURE);
      }
    } else {
      state->handshake_state = HANDSHAKE_STATE_FINISHED;
      unsigned char *material = export_keying_material(state->ssl);
      send_handshake_finished(state->env, *state->env->reply_to, 0, (char *)material);
      printf("handshake successful\n");
      fflush(stdout);
    } else {
      send_handshake_failed(state->env, *state->env->reply_to, 0);
      printf("handshake failed\n");
      fflush(stdout);
      exit(EXIT_FAILURE);
      break;
    }
  }

  return NULL;
}

static void *rx_function(void *user_data) {
  State *state = (State *) user_data;
  while(state->handshake_state != HANDSHAKE_STATE_FINISHED) {
    int bytes = recv(state->peer_fd, buf, len, 0);
    printf("Recv: %d\n", bytes);
    fflush(stdout);
    if (BIO_write(SSL_get_rbio(state->ssl), buf, bytes) != 1) {
      perror("Write error");
      exit(EXIT_FAILURE);
    }
  }
  return NULL;
}

static void *tx_function(void *user_data) {
  State *state = (State *) user_data;
  while (state->handshake_state != HANDSHAKE_STATE_FINISHED) {
    size_t pending_data_len = BIO_ctrl_pending(SSL_get_wbio(state->ssl));
    if (pending_data_len > 0) {
      char *data = (char *) malloc(pending_data_len * sizeof(char));
      if (BIO_read(SSL_get_wbio(state->ssl), data, pending_data_len) != (int) pending_data_len) {
        perror("Read error");
        exit(EXIT_FAILURE);
      }
      ssize_t bytes = send(state->peer_fd, data, pending_data_len, 0);
      printf("Sent %ld bytes\n", bytes);
      fflush(stdout);
      free(data);
    }
  }
  return NULL;
}

void handle_destroy_state(UnifexEnv *env, State *state) {
  UNIFEX_UNUSED(env);
  free(state->ssl_ctx);
  free(state->ssl);
}
