#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main() {
    int ps = sysconf(_SC_PAGESIZE);
    printf("Partial munmap demo\n");
    void *p = mmap(NULL, ps * 4, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { perror("mmap"); return 1; }
    printf("  Mapped 4 pages at %p\n", p);
    /* Unmap middle 2 pages - should split into lower (1 page) and upper (1 page) */
    if (munmap(p + ps, ps * 2) != 0) { perror("munmap partial"); return 1; }
    printf("  Unmapped middle 2 pages\n");
    printf("  Expected: 2 remaining regions of 1 page each\n");
    /* Clean up the remaining regions */
    munmap(p, ps);
    munmap(p + ps * 3, ps);
    printf("Partial munmap demo complete\n");
    return 0;
}
