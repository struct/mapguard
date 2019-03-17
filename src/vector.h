/* vector.h - A simple pointer vector */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>

#define VECTOR_MIN_SIZE 256

typedef struct {
	/* This vector only holds pointers */
    void **data;
    /* Index to the end of the vector */
    size_t end_slot;
    /* Size of the vector */
    size_t size;
    /* Index of the last known hole in the vector */
    size_t free_slot;
} vector_t;

typedef void (vector_delete_callback_t)(void *);
typedef void *(vector_for_each_callback_t)(void *, void *);

size_t vector_used(vector_t *v);
int vector_push(vector_t *v, void *ptr);
void *vector_pop(vector_t *v);
void *vector_get_end(vector_t *v);
void *vector_get_at(vector_t *v, size_t index);
void *vector_for_each(vector_t *v, vector_for_each_callback_t *fe, void *data);
void *vector_set_at(vector_t *v, int index, void *ptr);
void vector_delete_all(vector_t *v, vector_delete_callback_t *dc);
void vector_delete_at(vector_t *v, size_t index);
void vector_free(vector_t *v);
void vector_init(vector_t *v);