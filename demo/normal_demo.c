#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main() {
    int ps = sysconf(_SC_PAGESIZE);
    printf("Normal demo: mmap + munmap (no leaks expected)\n");
    void *p = mmap(NULL, ps * 4, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { perror("mmap"); return 1; }
    memset(p, 0x42, ps * 4);
    printf("  Mapped %d bytes at %p\n", ps * 4, p);
    if (munmap(p, ps * 4) != 0) { perror("munmap"); return 1; }
    printf("  Unmapped successfully\n");
    printf("Normal demo complete - report should show 0 outstanding leaks\n");
    return 0;
}
