#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "mapguard.h"

void *secret_data;

/* This is example is purely for demo purposes. Restricting
 * a page allocated for the heap is going to inevitably
 * result in an unintended crash */
void *worker_thread_enter(void *d) {
    protect_mapping(secret_data);

    /* This would result in a SEGV_PKUERR */
    /*uint8_t *v = &secret_data[2];
    LOG("In worker thread %x", *v);*/

    unprotect_mapping(secret_data, PROT_READ | PROT_WRITE);

    return OK;
}

int main(int argc, char *argv[]) {
    pthread_t worker_thread;

    secret_data = malloc(1024);
    memset(secret_data, 0x41, 1024);

    if(pthread_create(&worker_thread, NULL, worker_thread_enter, NULL)) {
        LOG("Failed to create thread");
        return ERROR;
    }

    uint8_t *v = &secret_data[2];
    LOG("In main thread %x", *v);

    if(pthread_join(worker_thread, NULL)) {
        LOG("Error waiting on thread");
        return ERROR;
    }

    free(secret_data);

    return OK;
}