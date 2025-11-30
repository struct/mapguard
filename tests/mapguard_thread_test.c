#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include "mapguard.h"

#define NUM_THREADS 4
#define ITERATIONS_PER_THREAD 1000
#define MAX_ALLOCATIONS 100

typedef struct {
    int thread_id;
    atomic_int *total_allocs;
    atomic_int *total_frees;
    atomic_int *errors;
} thread_data_t;

typedef struct {
    void *addr;
    size_t size;
} allocation_t;

static inline uint64_t xorshift64(uint64_t *state) {
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

void *worker_thread(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    allocation_t allocs[MAX_ALLOCATIONS];
    int num_allocs = 0;
    
    /* Per-thread random state seeded with thread ID and time */
    uint64_t rng_state = data->thread_id + time(NULL);
    
    for(int i = 0; i < ITERATIONS_PER_THREAD; i++) {
        uint64_t choice = xorshift64(&rng_state) % 100;
        
        if(choice < 60 && num_allocs < MAX_ALLOCATIONS) {
            /* Allocate memory (60% probability) */
            size_t sizes[] = {4096, 8192, 16384, 32768};
            size_t size = sizes[xorshift64(&rng_state) % 4];
            
            void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            
            if(ptr == MAP_FAILED) {
                fprintf(stderr, "[Thread %d] mmap failed at iteration %d\n", 
                       data->thread_id, i);
                atomic_fetch_add(data->errors, 1);
                continue;
            }
            
            /* Write to the memory to ensure it's accessible */
            memset(ptr, 0xAA + data->thread_id, size);
            
            allocs[num_allocs].addr = ptr;
            allocs[num_allocs].size = size;
            num_allocs++;
            
            atomic_fetch_add(data->total_allocs, 1);
            
        } else if(num_allocs > 0) {
            /* Free memory (40% probability, if we have allocations) */
            int idx = xorshift64(&rng_state) % num_allocs;
            
            /* Verify memory still contains our pattern before freeing */
            uint8_t *check = (uint8_t *)allocs[idx].addr;
            if(*check != (0xAA + data->thread_id)) {
                fprintf(stderr, "[Thread %d] Memory corruption detected at %p\n",
                       data->thread_id, allocs[idx].addr);
                atomic_fetch_add(data->errors, 1);
            }
            
            if(munmap(allocs[idx].addr, allocs[idx].size) != 0) {
                fprintf(stderr, "[Thread %d] munmap failed\n", data->thread_id);
                atomic_fetch_add(data->errors, 1);
            }
            
            atomic_fetch_add(data->total_frees, 1);
            
            /* Remove from tracking array by moving last element */
            allocs[idx] = allocs[num_allocs - 1];
            num_allocs--;
        }
        
        /* Occasionally do mprotect operations */
        if(num_allocs > 0 && choice < 10) {
            int idx = xorshift64(&rng_state) % num_allocs;
            
            if(mprotect(allocs[idx].addr, allocs[idx].size, PROT_READ) != 0) {
                fprintf(stderr, "[Thread %d] mprotect to PROT_READ failed\n", 
                       data->thread_id);
                atomic_fetch_add(data->errors, 1);
            } else {
                if(mprotect(allocs[idx].addr, allocs[idx].size, 
                           PROT_READ | PROT_WRITE) != 0) {
                    fprintf(stderr, "[Thread %d] mprotect to PROT_RW failed\n",
                           data->thread_id);
                    atomic_fetch_add(data->errors, 1);
                }
            }
        }
    }
    
    /* Clean up remaining allocations */
    for(int i = 0; i < num_allocs; i++) {
        munmap(allocs[i].addr, allocs[i].size);
        atomic_fetch_add(data->total_frees, 1);
    }
    
    printf("[Thread %d] Completed %d iterations\n", 
           data->thread_id, ITERATIONS_PER_THREAD);
    
    return NULL;
}

void *secret_data;

int main(int argc, char *argv[]) {
    pthread_t threads[NUM_THREADS];
    thread_data_t thread_data[NUM_THREADS];
    
    atomic_int total_allocs = 0;
    atomic_int total_frees = 0;
    atomic_int errors = 0;
    
    printf("Starting multi-threaded stress test:\n");
    printf("  Threads: %d\n", NUM_THREADS);
    printf("  Iterations per thread: %d\n", ITERATIONS_PER_THREAD);
    printf("  Max concurrent allocations per thread: %d\n", MAX_ALLOCATIONS);
    printf("\n");
    
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    /* Create threads */
    for(int i = 0; i < NUM_THREADS; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].total_allocs = &total_allocs;
        thread_data[i].total_frees = &total_frees;
        thread_data[i].errors = &errors;
        
        if(pthread_create(&threads[i], NULL, worker_thread, &thread_data[i]) != 0) {
            fprintf(stderr, "Failed to create thread %d\n", i);
            return 1;
        }
    }
    
    /* Wait for all threads to complete */
    for(int i = 0; i < NUM_THREADS; i++) {
        if(pthread_join(threads[i], NULL) != 0) {
            fprintf(stderr, "Failed to join thread %d\n", i);
            return 1;
        }
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double elapsed = (end.tv_sec - start.tv_sec) + 
                    (end.tv_nsec - start.tv_nsec) / 1000000000.0;
    
    printf("\n=== Test Results ===\n");
    printf("Total allocations: %d\n", atomic_load(&total_allocs));
    printf("Total frees: %d\n", atomic_load(&total_frees));
    printf("Errors: %d\n", atomic_load(&errors));
    printf("Elapsed time: %.2f seconds\n", elapsed);
    printf("Operations per second: %.0f\n", 
           (atomic_load(&total_allocs) + atomic_load(&total_frees)) / elapsed);
    
    if(atomic_load(&errors) > 0) {
        printf("\n*** TEST FAILED: %d errors detected ***\n", 
               atomic_load(&errors));
        return 1;
    }
    
    printf("\n*** TEST PASSED ***\n");
    return 0;
}
