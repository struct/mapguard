#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define NUM_ITERATIONS 10000
#define ALLOCATION_SIZE (4096 * 4)
#define VARIED_SIZE_COUNT 1000

typedef struct {
    void *ptr;
    size_t size;
} allocation_t;

static inline double timespec_diff_ms(struct timespec *start, struct timespec *end) {
    return (end->tv_sec - start->tv_sec) * 1000.0 +
           (end->tv_nsec - start->tv_nsec) / 1000000.0;
}

void test_simple_alloc_free(void) {
    struct timespec start, end;

    clock_gettime(CLOCK_MONOTONIC, &start);

    for(int i = 0; i < NUM_ITERATIONS; i++) {
        void *ptr = mmap(NULL, ALLOCATION_SIZE, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if(ptr == MAP_FAILED) {
            fprintf(stderr, "mmap failed at iteration %d\n", i);
            exit(1);
        }

        munmap(ptr, ALLOCATION_SIZE);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    double elapsed = timespec_diff_ms(&start, &end);
    printf("simple_alloc_free,%d,%.2f,%.2f\n",
           NUM_ITERATIONS, elapsed, NUM_ITERATIONS / (elapsed / 1000.0));
}

void test_alloc_write_free(void) {
    struct timespec start, end;

    clock_gettime(CLOCK_MONOTONIC, &start);

    for(int i = 0; i < NUM_ITERATIONS; i++) {
        void *ptr = mmap(NULL, ALLOCATION_SIZE, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if(ptr == MAP_FAILED) {
            fprintf(stderr, "mmap failed at iteration %d\n", i);
            exit(1);
        }

        memset(ptr, 0xAA, ALLOCATION_SIZE);

        munmap(ptr, ALLOCATION_SIZE);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    double elapsed = timespec_diff_ms(&start, &end);
    printf("alloc_write_free,%d,%.2f,%.2f\n",
           NUM_ITERATIONS, elapsed, NUM_ITERATIONS / (elapsed / 1000.0));
}

void test_batch_alloc_then_free(void) {
    struct timespec start, end;
    allocation_t *allocs = malloc(NUM_ITERATIONS * sizeof(allocation_t));

    clock_gettime(CLOCK_MONOTONIC, &start);

    for(int i = 0; i < NUM_ITERATIONS; i++) {
        allocs[i].ptr = mmap(NULL, ALLOCATION_SIZE, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        allocs[i].size = ALLOCATION_SIZE;
        if(allocs[i].ptr == MAP_FAILED) {
            fprintf(stderr, "mmap failed at iteration %d\n", i);
            exit(1);
        }
    }

    for(int i = 0; i < NUM_ITERATIONS; i++) {
        munmap(allocs[i].ptr, allocs[i].size);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    double elapsed = timespec_diff_ms(&start, &end);
    printf("batch_alloc_then_free,%d,%.2f,%.2f\n",
           NUM_ITERATIONS, elapsed, NUM_ITERATIONS / (elapsed / 1000.0));

    free(allocs);
}

void test_varied_sizes(void) {
    struct timespec start, end;
    size_t sizes[] = {4096, 8192, 16384, 32768, 65536};
    int num_sizes = sizeof(sizes) / sizeof(sizes[0]);

    clock_gettime(CLOCK_MONOTONIC, &start);

    for(int i = 0; i < VARIED_SIZE_COUNT; i++) {
        size_t size = sizes[i % num_sizes];
        void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if(ptr == MAP_FAILED) {
            fprintf(stderr, "mmap failed at iteration %d\n", i);
            exit(1);
        }

        munmap(ptr, size);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    double elapsed = timespec_diff_ms(&start, &end);
    printf("varied_sizes,%d,%.2f,%.2f\n",
           VARIED_SIZE_COUNT, elapsed, VARIED_SIZE_COUNT / (elapsed / 1000.0));
}

void test_mprotect_transitions(void) {
    struct timespec start, end;

    clock_gettime(CLOCK_MONOTONIC, &start);

    for(int i = 0; i < NUM_ITERATIONS / 10; i++) {
        void *ptr = mmap(NULL, ALLOCATION_SIZE, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if(ptr == MAP_FAILED) {
            fprintf(stderr, "mmap failed at iteration %d\n", i);
            exit(1);
        }

        mprotect(ptr, ALLOCATION_SIZE, PROT_READ);
        mprotect(ptr, ALLOCATION_SIZE, PROT_READ | PROT_WRITE);

        munmap(ptr, ALLOCATION_SIZE);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    double elapsed = timespec_diff_ms(&start, &end);
    printf("mprotect_transitions,%d,%.2f,%.2f\n",
           NUM_ITERATIONS / 10, elapsed, (NUM_ITERATIONS / 10) / (elapsed / 1000.0));
}

void test_large_allocations(void) {
    struct timespec start, end;
    size_t large_size = 1024 * 1024;

    clock_gettime(CLOCK_MONOTONIC, &start);

    for(int i = 0; i < 1000; i++) {
        void *ptr = mmap(NULL, large_size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if(ptr == MAP_FAILED) {
            fprintf(stderr, "mmap failed at iteration %d\n", i);
            exit(1);
        }

        munmap(ptr, large_size);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    double elapsed = timespec_diff_ms(&start, &end);
    printf("large_allocations,1000,%.2f,%.2f\n",
           elapsed, 1000 / (elapsed / 1000.0));
}

void test_partial_munmap(void) {
    struct timespec start, end;
    size_t size = 16384; /* 4 pages */

    clock_gettime(CLOCK_MONOTONIC, &start);

    for(int i = 0; i < NUM_ITERATIONS / 10; i++) {
        void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if(ptr == MAP_FAILED) {
            fprintf(stderr, "mmap failed at iteration %d\n", i);
            exit(1);
        }

        /* Test different unmap patterns */
        if(i % 3 == 0) {
            /* Unmap from beginning */
            munmap(ptr, 4096);
            munmap(ptr + 4096, 12288);
        } else if(i % 3 == 1) {
            /* Unmap from end */
            munmap(ptr + 12288, 4096);
            munmap(ptr, 12288);
        } else {
            /* Unmap from middle - creates split! */
            munmap(ptr + 4096, 8192);
            munmap(ptr, 4096);
            munmap(ptr + 12288, 4096);
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    double elapsed = timespec_diff_ms(&start, &end);
    printf("partial_munmap,%d,%.2f,%.2f\n",
           NUM_ITERATIONS / 10, elapsed, (NUM_ITERATIONS / 10) / (elapsed / 1000.0));
}

int main(void) {
    printf("test_name,iterations,time_ms,ops_per_sec\n");

    test_simple_alloc_free();
    test_alloc_write_free();
    test_batch_alloc_then_free();
    test_varied_sizes();
    test_mprotect_transitions();
    test_large_allocations();
    test_partial_munmap();

    return 0;
}
