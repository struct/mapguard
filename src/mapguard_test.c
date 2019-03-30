/* Map Guard test
 * Copyright Chris Rohlf - 2019 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <sys/mman.h>

#include "mapguard.h"

#define OK 0
#define ERROR -1
#define MG_POISON_BYTE 0xde
#define STATIC_ADDRESS 0x7f3bffaaa000

#if DEBUG
    #define LOG_ERROR(msg, ...) \
        fprintf(stderr, "[LOG][%d](%s) (%s) - " msg "\n", getpid(), __FUNCTION__, strerror(errno), ##__VA_ARGS__); \
        fflush(stderr);

    #define LOG(msg, ...)   \
        fprintf(stdout, "[LOG][%d](%s) " msg "\n", getpid(), __FUNCTION__, ##__VA_ARGS__); \
        fflush(stdout);
#else
    #define LOG_ERROR(...)
    #define LOG(...)
#endif

#define ALLOC_SIZE 4096 * 8

void *map_memory(char *desc, int prot) {
    uint8_t *ptr = mmap(0, ALLOC_SIZE, prot, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);

    if(ptr != MAP_FAILED) {
        LOG("Successfully mmapped %s memory @ %p", desc, ptr);
    } else {
        LOG("Failed to map %s memory", desc);
    }

    return ptr;
}

int32_t unmap_memory(void *ptr) {
    int32_t ret = munmap(ptr, ALLOC_SIZE);

    if(ret == 0) {
        LOG("Successfully munmapped memory @ %p", ptr);
    } else {
        LOG("Failed to munmap memory @ %p", ptr);
    }

    return ret;
}

int32_t unmap_remapped_memory(void *ptr) {
    int32_t ret = munmap(ptr, ALLOC_SIZE*2);

    if(ret == 0) {
        LOG("Successfully munmapped remapped memory @ %p", ptr);
    } else {
        LOG("Failed to munmap remapped memory @ %p", ptr);
    }

    return ret;
}

void *remap_memory(char *desc, void *ptr) {
    void *mptr = mremap(ptr, ALLOC_SIZE, ALLOC_SIZE*2, MREMAP_MAYMOVE);

    if(mptr != MAP_FAILED) {
        LOG("Successfully remapped %s memory %p @ %p", desc, ptr, mptr);
    } else {
        LOG("Failed to remap %s memory", desc);
        abort();
    }

    return mptr;
}

void map_rw_memory() {
    void *ptr = map_memory("RW", PROT_READ|PROT_WRITE);

    if(ptr == MAP_FAILED) {
        LOG("Failed to map RW memory");
        abort();
    } else {
        LOG("Test passed");
    }

    unmap_memory(ptr);
}

void map_rwx_memory() {
    void *ptr = map_memory("RWX", PROT_READ|PROT_WRITE|PROT_EXEC);

    if(ptr != MAP_FAILED) {
        LOG("Successfully mapped RWX memory");
        abort();
    } else {
        LOG("Test passed");
    }
}

void check_x_to_w() {
    void *ptr = map_memory("R-X", PROT_READ|PROT_EXEC);

    if(ptr == MAP_FAILED) {
        LOG("Failed to map R-X memory");
        abort();
    }

    int32_t ret = mprotect(ptr, ALLOC_SIZE, PROT_READ|PROT_WRITE);

    if(ret != ERROR) {
        LOG("Successfully mprotect'd memory R-X to RW-");
        abort();
    } else {
        LOG("Test passed");
    }

    unmap_memory(ptr);
}

void map_rw_then_x_memory() {
    void *ptr = map_memory("RW", PROT_READ|PROT_WRITE);

    if(ptr == MAP_FAILED) {
        LOG("Failed to map RW memory");
        abort();
    }

    int32_t ret = mprotect(ptr, ALLOC_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC);

    if(ret != ERROR) {
        LOG("Successfully mprotect'd memory RWX");
        abort();
    } else {
        LOG("Test passed");
    }

    unmap_memory(ptr);
}

void map_then_mremap() {
    void *ptr = map_memory("RW", PROT_READ|PROT_WRITE);

    if(ptr == MAP_FAILED) {
        LOG("Failed to map RW memory");
        abort();
    }

    ptr = remap_memory("Remap", ptr);

    if(ptr == MAP_FAILED) {
        LOG("Failed to remap memory");
        abort();
    } else {
        LOG("Test passed");
    }

    unmap_remapped_memory(ptr);
}

void map_static_address() {
    uint8_t *ptr = mmap((void *) STATIC_ADDRESS, ALLOC_SIZE, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);

    if(ptr != MAP_FAILED) {
        LOG("Successfully mmapped memory @ %lx", STATIC_ADDRESS);
    } else {
        LOG("Test passed");
    }
}

void check_poison_bytes() {
    void *ptr = map_memory("Poison Bytes", PROT_READ|PROT_WRITE);

    if(ptr == MAP_FAILED) {
        LOG("Failed to map Poison Bytes memory");
        abort();
    }

    uint8_t *byte = &ptr[128];

    if(*byte != MG_POISON_BYTE) {
        LOG("Failed to find poison byte 0x%x, found 0x%x", MG_POISON_BYTE, *byte);
    } else {
        LOG("Test passed")
    }

    unmap_memory(ptr);
}

void check_map_partial_unmap_bottom() {
    uint8_t *ptr = mmap(0, 8192, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);

    if(ptr != MAP_FAILED) {
        LOG("Successfully mmapped memory @ %p", ptr);
    } else {
        LOG("Failed to map memory");
    }

    int ret = munmap(ptr, 4096);

    if(ret != 0) {
        LOG("Failed to unmap partial page mapping");
        abort();
    } else {
        LOG("Successfully unmapped partial bottom page mapping");
    }

    munmap(ptr+4096, 4096);
}

void check_map_partial_unmap_top() {
    uint8_t *ptr = mmap(0, 8192, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);

    if(ptr != MAP_FAILED) {
        LOG("Successfully mmapped memory @ %p", ptr);
    } else {
        LOG("Failed to map memory");
    }

    int ret = munmap(ptr+4096, 4096);

    if(ret != 0) {
        LOG("Failed to unmap partial page mapping");
        abort();
    } else {
        LOG("Successfully unmapped partial top page mapping");
    }

    munmap(ptr, 4096);
}

#ifdef MPK_SUPPORT
void check_mpk_xom() {
    char *x86_nops_cc = "\x90\x90\x90\x90\xcc";
    void *ptr = memcpy_xom(4096, x86_nops_cc, strlen(x86_nops_cc));

    void*(*code_pointer)();
    code_pointer = (void *) ptr;
    /* Should execute the code at the XOM mapping
     * but will eventually crash */
    (code_pointer)();

    /* Should result in SEGV_PKUERR */
    int8_t *v = &ptr[2];
    LOG("XOM Read Value = %02x", *v);
}

void check_protect_mapping() {
    void *ptr = map_memory("RW", PROT_READ|PROT_WRITE);
    int32_t ret = protect_mapping(ptr);

    if(ret != 0) {
        LOG("Failed to protect memory mapping @ %p", ptr);
        abort();
    } else {
        LOG("Successfully protected memory @ %p", ptr);
    }

    ret = unprotect_mapping(ptr, PROT_READ|PROT_WRITE);

    if(ret != 0) {
        LOG("Failed to unprotect memory mapping @ %p", ptr);
        abort();
    } else {
        LOG("Successfully unprotected memory @ %p", ptr);
    }

    unmap_memory(ptr);
}
#endif

int main(int argc, char *argv[]) {
    map_rw_memory();
    map_rwx_memory();
    map_rw_then_x_memory();
    map_then_mremap();
    map_static_address();
    check_poison_bytes();
    check_x_to_w();
    check_map_partial_unmap_bottom();
    check_map_partial_unmap_top();
    /* Temporarily disabled while I work on MPK support
    check_mpk_xom(); */

#ifdef MPK_SUPPORT
    check_protect_mapping();
#endif

    protect_code();
    unprotect_code();

    return OK;
}