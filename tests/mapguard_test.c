/* MapGuard tests
 * Copyright Chris Rohlf - 2025 */

#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "mapguard.h"

#define STATIC_ADDRESS 0x7f3bffaaa000
int page_size;
int alloc_size;

void *map_memory(char *desc, int prot) {
    return mmap(0, alloc_size, prot, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
}

int32_t unmap_memory(void *ptr) {
    return munmap(ptr, alloc_size);
}

int32_t unmap_remapped_memory(void *ptr) {
    return munmap(ptr, alloc_size);
}

void *remap_memory_test(char *desc, void *ptr) {
    void *mptr = mremap(ptr, alloc_size, alloc_size * 2, MREMAP_MAYMOVE);
    if(mptr != MAP_FAILED) {
        LOG("Success: remapped %s memory %p @ %p", desc, ptr, mptr);
    } else {
        LOG("Failure: remap %s memory", desc);
    }

    return mptr;
}

void map_rw_memory_test() {
    void *ptr = map_memory("RW", PROT_READ | PROT_WRITE);

    if(ptr == MAP_FAILED) {
        LOG("Failure: map RW memory");
    } else {
        LOG("Success: mapped RW memory");
    }

    unmap_memory(ptr);
}

void map_rwx_memory_test() {
    void *ptr = map_memory("RWX", PROT_READ | PROT_WRITE | PROT_EXEC);

    if(ptr != MAP_FAILED) {
        LOG("Failure: mapped RWX memory");
    } else {
        LOG("Success: failed to map RWX memory");
    }
}

void check_x_to_w_test() {
    void *ptr = map_memory("R-X", PROT_READ | PROT_EXEC);

    if(ptr == MAP_FAILED) {
        LOG("Failure: to map R-X memory");
    }

    int32_t ret = mprotect(ptr, page_size * 16, PROT_READ | PROT_WRITE);

    if(ret != ERROR) {
        LOG("Failure: allowed mprotect R-X to RW-");
    } else {
        LOG("Success: prevented R-X to R-W");
    }

    unmap_memory(ptr);
}

void map_rw_then_x_memory_test() {
    void *ptr = map_memory("RW", PROT_READ | PROT_WRITE);

    if(ptr == MAP_FAILED) {
        LOG("Failure: to map RW memory");
    }

    int32_t ret = mprotect(ptr, page_size * 16, PROT_READ | PROT_WRITE | PROT_EXEC);

    if(ret != ERROR) {
        LOG("Failure: allowed mprotect of RWX");
    } else {
        LOG("Success: prevented RWX mprotect");
    }

    unmap_memory(ptr);
}

void map_then_mremap_test() {
    void *ptr = map_memory("RW", PROT_READ | PROT_WRITE);

    if(ptr == MAP_FAILED) {
        LOG("Failure: to map RW memory");
    }
    LOG("mapped RW memory %p", ptr);
    ptr = remap_memory_test("Remap", ptr);

    if(ptr == MAP_FAILED) {
        LOG("Failure: to remap memory");
    } else {
        LOG("Success: remapped memory");
    }

    unmap_remapped_memory(ptr);
}

void map_static_address_test() {
    uint8_t *ptr = mmap((void *) STATIC_ADDRESS, page_size * 16, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    if(ptr != MAP_FAILED) {
        LOG("Failure: mmapped memory at static address @ %lx", STATIC_ADDRESS);
    } else {
        LOG("Success: prevented mmap at static address");
    }
}

void check_poison_bytes_test() {
    void *ptr = map_memory("Poison Bytes", PROT_READ | PROT_WRITE);

    if(ptr == MAP_FAILED) {
        LOG("Failure: to map poison bytes memory");
    }

    uint8_t *byte = &ptr[128];

    if(*byte != MG_POISON_BYTE) {
        LOG("Failure: to find poison byte 0x%x, found 0x%x", MG_POISON_BYTE, *byte);
    } else {
        LOG("Success: mapped memory with poison bytes")
    }

    unmap_memory(ptr);
}

void unmap_partial_rw_memory_test() {
    void *ptr = mmap(0, page_size * 3, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    if(ptr != MAP_FAILED) {
        LOG("Success: mmapped memory @ %p", ptr);
    } else {
        LOG("Failure: to map memory");
    }

    int ret = munmap(ptr + page_size, page_size);

    if(ret != 0) {
        LOG("Failure: to unmap bottom page");
    } else {
        LOG("Success: unmapped bottom page");
    }

    munmap(ptr, page_size);
    munmap(ptr + (page_size * 2), 4096);
}

void check_map_partial_unmap_bottom_test() {
    uint8_t *ptr = mmap(0, 8192, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    if(ptr != MAP_FAILED) {
        LOG("Success: mmapped memory @ %p", ptr);
    } else {
        LOG("Failure: to map memory");
    }

    int ret = munmap(ptr, 4096);

    if(ret != 0) {
        LOG("Failure: to unmap bottom page");
    } else {
        LOG("Success: unmapped bottom page");
    }

    munmap(ptr + 4096, 4096);
}

void check_map_partial_unmap_top_test() {
    uint8_t *ptr = mmap(0, 8192, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    if(ptr != MAP_FAILED) {
        LOG("Success: mmapped memory @ %p", ptr);
    } else {
        LOG("Failure: to map memory");
    }

    int ret = munmap(ptr + 4096, 4096);

    if(ret != 0) {
        LOG("Failure: to unmap top page");
    } else {
        LOG("Success: unmapped top page");
    }

    munmap(ptr, 4096);
}

/* Case 1: Full unmap test */
void check_full_unmap_test() {
    uint8_t *ptr = mmap(0, page_size * 8, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    if(ptr == MAP_FAILED) {
        LOG("Failure: to map memory for full unmap test");
        return;
    }

    LOG("Case 1 Test: Full unmap of %p (size %d)", ptr, page_size * 8);

    int ret = munmap(ptr, page_size * 8);

    if(ret != 0) {
        LOG("Failure: to fully unmap memory");
    } else {
        LOG("Success: fully unmapped memory");
    }
}

/* Case 2: Unmap from beginning */
void check_unmap_from_beginning_test() {
    uint8_t *ptr = mmap(0, page_size * 8, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    if(ptr == MAP_FAILED) {
        LOG("Failure: to map memory for beginning unmap test");
        return;
    }

    LOG("Case 2 Test: Unmap first 3 pages from %p", ptr);

    /* Unmap first 3 pages */
    int ret = munmap(ptr, page_size * 3);

    if(ret != 0) {
        LOG("Failure: to unmap from beginning");
    } else {
        LOG("Success: unmapped from beginning, remaining region starts at %p", ptr + (page_size * 3));
    }

    /* Clean up remaining pages */
    munmap(ptr + (page_size * 3), page_size * 5);
}

/* Case 3: Unmap from middle to end */
void check_unmap_middle_to_end_test() {
    uint8_t *ptr = mmap(0, page_size * 8, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    if(ptr == MAP_FAILED) {
        LOG("Failure: to map memory for middle-to-end unmap test");
        return;
    }

    LOG("Case 3 Test: Unmap from middle (page 4) to end from %p", ptr);

    /* Unmap from page 4 to the end */
    int ret = munmap(ptr + (page_size * 3), page_size * 5);

    if(ret != 0) {
        LOG("Failure: to unmap from middle to end");
    } else {
        LOG("Success: unmapped from middle to end, remaining region is %p (size %d)", ptr, page_size * 3);
    }

    /* Clean up remaining pages */
    munmap(ptr, page_size * 3);
}

/* Case 4: Unmap single page from middle (creates split with 1 page hole) */
void check_unmap_single_page_middle_test() {
    uint8_t *ptr = mmap(0, page_size * 8, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    if(ptr == MAP_FAILED) {
        LOG("Failure: to map memory for single page middle unmap test");
        return;
    }

    LOG("Case 4a Test: Unmap single page (page 4) from middle of %p", ptr);

    /* Unmap page 4 (creates a 1-page hole) */
    int ret = munmap(ptr + (page_size * 3), page_size);

    if(ret != 0) {
        LOG("Failure: to unmap single page from middle");
    } else {
        LOG("Success: unmapped single page from middle, created 2 regions");
        LOG("  Lower region: %p (size %d)", ptr, page_size * 3);
        LOG("  Upper region: %p (size %d)", ptr + (page_size * 4), page_size * 4);
    }

    /* Clean up both regions */
    munmap(ptr, page_size * 3);
    munmap(ptr + (page_size * 4), page_size * 4);
}

/* Case 4: Unmap 2 pages from middle (reuse both as guards) */
void check_unmap_two_pages_middle_test() {
    uint8_t *ptr = mmap(0, page_size * 10, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    if(ptr == MAP_FAILED) {
        LOG("Failure: to map memory for two page middle unmap test");
        return;
    }

    LOG("Case 4b Test: Unmap 2 pages (pages 4-5) from middle of %p", ptr);

    /* Unmap 2 pages (pages 4-5) */
    int ret = munmap(ptr + (page_size * 3), page_size * 2);

    if(ret != 0) {
        LOG("Failure: to unmap 2 pages from middle");
    } else {
        LOG("Success: unmapped 2 pages from middle, created 2 regions with guards");
        LOG("  Lower region: %p (size %d)", ptr, page_size * 3);
        LOG("  Upper region: %p (size %d)", ptr + (page_size * 5), page_size * 5);
    }

    /* Clean up both regions */
    munmap(ptr, page_size * 3);
    munmap(ptr + (page_size * 5), page_size * 5);
}

/* Case 4: Unmap 3 pages from middle (reuse first/last as guards, unmap middle) */
void check_unmap_three_pages_middle_test() {
    uint8_t *ptr = mmap(0, page_size * 10, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    if(ptr == MAP_FAILED) {
        LOG("Failure: to map memory for three page middle unmap test");
        return;
    }

    LOG("Case 4c Test: Unmap 3 pages (pages 4-6) from middle of %p", ptr);

    /* Unmap 3 pages (pages 4-6) */
    int ret = munmap(ptr + (page_size * 3), page_size * 3);

    if(ret != 0) {
        LOG("Failure: to unmap 3 pages from middle");
    } else {
        LOG("Success: unmapped 3 pages from middle, created 2 regions with guards");
        LOG("  Lower region: %p (size %d)", ptr, page_size * 3);
        LOG("  Upper region: %p (size %d)", ptr + (page_size * 6), page_size * 4);
    }

    /* Clean up both regions */
    munmap(ptr, page_size * 3);
    munmap(ptr + (page_size * 6), page_size * 4);
}

/* Case 4: Unmap 5 pages from middle (stress test with more pages) */
void check_unmap_five_pages_middle_test() {
    uint8_t *ptr = mmap(0, alloc_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    if(ptr == MAP_FAILED) {
        LOG("Failure: to map memory for five page middle unmap test");
        return;
    }

    LOG("Case 4d Test: Unmap 5 pages (pages 6-10) from middle of %p", ptr);

    /* Unmap 5 pages from the middle */
    int ret = munmap(ptr + (page_size * 5), page_size * 5);

    if(ret != 0) {
        LOG("Failure: to unmap 5 pages from middle");
    } else {
        LOG("Success: unmapped 5 pages from middle, created 2 regions with guards");
        LOG("  Lower region: %p (size %d)", ptr, page_size * 5);
        LOG("  Upper region: %p (size %d)", ptr + (page_size * 10), page_size * 6);
    }

    /* Clean up both regions */
    munmap(ptr, page_size * 5);
    munmap(ptr + (page_size * 10), page_size * 6);
}

/* Stress test: Multiple sequential partial unmaps */
void check_multiple_partial_unmaps_test() {
    uint8_t *ptr = mmap(0, page_size * 20, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    if(ptr == MAP_FAILED) {
        LOG("Failure: to map memory for multiple partial unmap test");
        return;
    }

    LOG("Stress Test: Multiple partial unmaps on %p", ptr);

    /* Unmap from beginning (Case 2) */
    int ret = munmap(ptr, page_size * 3);
    if(ret != 0) {
        LOG("Failure: first partial unmap");
        munmap(ptr + (page_size * 3), page_size * 17);
        return;
    }
    LOG("  Step 1: Unmapped first 3 pages");

    /* Unmap from middle (Case 4) - creates split */
    ret = munmap(ptr + (page_size * 8), page_size * 4);
    if(ret != 0) {
        LOG("Failure: middle partial unmap");
        munmap(ptr + (page_size * 3), page_size * 5);
        munmap(ptr + (page_size * 12), page_size * 8);
        return;
    }
    LOG("  Step 2: Unmapped 4 pages from middle, created split");

    /* Clean up remaining regions */
    munmap(ptr + (page_size * 3), page_size * 5);  /* Lower region after split */
    munmap(ptr + (page_size * 12), page_size * 8); /* Upper region after split */

    LOG("Success: completed multiple partial unmaps");
}

int main(int argc, char *argv[]) {
    page_size = sysconf(_SC_PAGESIZE);
    alloc_size = page_size * 16;

    for(int i = 0; i < 16; i++) {
        map_rw_memory_test();
        map_rwx_memory_test();
        map_rw_then_x_memory_test();
        map_then_mremap_test();
        map_static_address_test();
        check_poison_bytes_test();
        check_x_to_w_test();
        check_map_partial_unmap_bottom_test();
        check_map_partial_unmap_top_test();
        unmap_partial_rw_memory_test();
        check_full_unmap_test();
        check_unmap_from_beginning_test();
        check_unmap_middle_to_end_test();
        check_unmap_single_page_middle_test();
        check_unmap_two_pages_middle_test();
        check_unmap_three_pages_middle_test();
        check_unmap_five_pages_middle_test();
        check_multiple_partial_unmaps_test();
    }

    LOG("Done testing");
    return OK;
}