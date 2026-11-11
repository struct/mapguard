#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main() {
    int ps = sysconf(_SC_PAGESIZE);
    printf("Leak demo: intentional leaks\n");
    void *p1 = mmap(NULL, ps * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *p2 = mmap(NULL, ps * 4, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *p3 = mmap(NULL, ps * 1, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p1 == MAP_FAILED || p2 == MAP_FAILED || p3 == MAP_FAILED) { perror("mmap"); return 1; }
    printf("  Mapped p1=%p (%d B), p2=%p (%d B), p3=%p (%d B)\n", p1, ps*2, p2, ps*4, p3, ps*1);
    munmap(p2, ps * 4);  /* Only free p2 */
    printf("  Freed only p2\n");
    printf("Leak demo complete - report should show 2 outstanding leaks (p1, p3)\n");
    return 0;
}
