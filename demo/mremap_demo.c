#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main() {
    int ps = sysconf(_SC_PAGESIZE);
    printf("mremap demo\n");
    void *p = mmap(NULL, ps * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { perror("mmap"); return 1; }
    printf("  Mapped 2 pages at %p\n", p);
    memset(p, 0xAA, ps * 2);
    void *np = mremap(p, ps * 2, ps * 8, MREMAP_MAYMOVE);
    if (np == MAP_FAILED) { perror("mremap"); return 1; }
    printf("  Remapped to 8 pages at %p (may have moved from %p)\n", np, p);
    /* Verify first bytes are still 0xAA */
    unsigned char *bytes = (unsigned char *)np;
    if (bytes[0] == 0xAA && bytes[ps-1] == 0xAA) {
        printf("  Data preserved after mremap\n");
    }
    munmap(np, ps * 8);
    printf("mremap demo complete - should show 0 outstanding leaks\n");
    return 0;
}
