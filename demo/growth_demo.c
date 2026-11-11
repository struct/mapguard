#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main() {
    int ps = sysconf(_SC_PAGESIZE);
    size_t block = 256 * 1024; /* 256 KiB per block */
    int count = 12;
    printf("Growth demo: allocating %d blocks of %zu bytes without freeing\n", count, block);
    for (int i = 0; i < count; i++) {
        void *p = mmap(NULL, block, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) { perror("mmap"); return 1; }
        memset(p, i & 0xFF, block);
        printf("  [%d] Mapped %zu bytes at %p (total ~%zu KiB)\n", i, block, p, (size_t)(i+1)*block/1024);
        usleep(300000); /* 300ms between allocs so snapshots can observe growth */
    }
    printf("Growth demo complete - report should show growth warning and %d outstanding leaks\n", count);
    return 0;
}
