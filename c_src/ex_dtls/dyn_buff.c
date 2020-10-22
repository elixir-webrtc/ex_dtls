#include "dyn_buff.h"

DynBuff *dyn_buff_new(int size) {
  DynBuff *dyn_buff = (DynBuff *)malloc(sizeof(DynBuff));
  dyn_buff->data = (char *)malloc(size * sizeof(char));
  if (dyn_buff->data == NULL) {
    fprintf(stderr, "Cannot allocate new dyn_buff with size: %d bytes", size);
    free(dyn_buff);
    exit(EXIT_FAILURE);
  }
  memset(dyn_buff->data, 0, size);
  dyn_buff->size = size;
  dyn_buff->data_size = 0;
  return dyn_buff;
}

void dyn_buff_insert(DynBuff *dyn_buff, char *data, int size) {
  if (dyn_buff->size - dyn_buff->data_size < size) {
    int new_size = 2 * (dyn_buff->data_size + size);
    dyn_buff->data = (char *)realloc(dyn_buff->data, new_size);
    if (dyn_buff->data == NULL) {
      fprintf(stderr, "Cannot realloc dyn_buff to size: %d bytes", new_size);
      dyn_buff_free(dyn_buff);
      exit(EXIT_FAILURE);
    }
    dyn_buff->size = new_size;
  }
  memcpy(dyn_buff->data + dyn_buff->data_size, data, size);
  dyn_buff->data_size += size;
}

void dyn_buff_free(DynBuff *dyn_buff) { free(dyn_buff->data); }
