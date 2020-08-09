/* Map Guard test
 * Copyright Chris Rohlf - 2020 */

#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "../mapguard.h"

#define STATIC_ADDRESS 0x7f3bffaaa000
#define ALLOC_SIZE 4096 * 8

void *map_memory(char *desc, int prot) {
    return mmap(0, ALLOC_SIZE, prot, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
}

int32_t unmap_memory(void *ptr) {
    return munmap(ptr, ALLOC_SIZE);
}

int32_t unmap_remapped_memory(void *ptr) {
    return munmap(ptr, ALLOC_SIZE * 2);
}

void *remap_memory_test(char *desc, void *ptr) {
    void *mptr = mremap(ptr, ALLOC_SIZE, ALLOC_SIZE * 2, MREMAP_MAYMOVE);

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

    int32_t ret = mprotect(ptr, ALLOC_SIZE, PROT_READ | PROT_WRITE);

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

    int32_t ret = mprotect(ptr, ALLOC_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC);

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

    ptr = remap_memory_test("Remap", ptr);

    if(ptr == MAP_FAILED) {
        LOG("Failure: to remap memory");
    } else {
        LOG("Success: remapped memory");
    }

    unmap_remapped_memory(ptr);
}

void map_static_address_test() {
    uint8_t *ptr = mmap((void *) STATIC_ADDRESS, ALLOC_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

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

#if MPK_SUPPORT
void check_mpk_xom_test() {
    char *x86_nops_cc = "\x90\x90\x90\x90\xcc";
    void *ptr = memcpy_xom(4096, x86_nops_cc, strlen(x86_nops_cc));

    void *(*code_pointer)();
    code_pointer = (void *) ptr;
    /* Should execute the code at the XOM mapping
     * but will eventually crash */
    (code_pointer)();

    /* Should result in SEGV_PKUERR */
    int8_t *v = &ptr[2];
    LOG("XOM Read Value = %02x", *v);
    LOG("Test passed");
}

void check_protect_mapping_test() {
    void *ptr = map_memory("RW", PROT_READ | PROT_WRITE);
    int32_t ret = protect_mapping(ptr);

    if(ret != 0) {
        LOG("Failure: to protect memory mapping @ %p", ptr);
    } else {
        LOG("Success: protected memory @ %p", ptr);
    }

    ret = unprotect_mapping(ptr, PROT_READ | PROT_WRITE);

    if(ret != 0) {
        LOG("Failure: to unprotect memory mapping @ %p", ptr);
    } else {
        LOG("Success: unprotected memory @ %p", ptr);
    }

    unmap_memory(ptr);
}
#endif

int main(int argc, char *argv[]) {
    map_rw_memory_test();
    map_rwx_memory_test();
    map_rw_then_x_memory_test();
    map_then_mremap_test();
    map_static_address_test();
    check_poison_bytes_test();
    check_x_to_w_test();
    check_map_partial_unmap_bottom_test();
    check_map_partial_unmap_top_test();

#if MPK_SUPPORT
    //check_mpk_xom_test();
    check_protect_mapping_test();
    protect_code();
    unprotect_code();
#endif

    return OK;
}