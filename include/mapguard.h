/* Reference implementation of map guard
 * Copyright Chris Rohlf - 2021 */

#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <syslog.h>
#include <unistd.h>

#if MPK_SUPPORT
#include <elf.h>
#endif

#include "../vector_t/vector.h"

#define OK 0
#define ERROR -1
#define GUARD_PAGE_COUNT 2

#define SYSLOG(msg, ...)                       \
    if(g_mapguard_policy.enable_syslog) {      \
        syslog(LOG_ALERT, msg, ##__VA_ARGS__); \
    }

/* If you want to log security policy violations then
 * modifying this macro is the easiest way to do it */
#if DEBUG
#define LOG_ERROR(msg, ...)                                                                                    \
    fprintf(stderr, "[LOG][%d](%s) (%s) - " msg "\n", getpid(), __FUNCTION__, strerror(errno), ##__VA_ARGS__); \
    fflush(stderr);

#define LOG(msg, ...)                                                                  \
    fprintf(stdout, "[LOG][%d](%s) " msg "\n", getpid(), __FUNCTION__, ##__VA_ARGS__); \
    fflush(stdout);
#else
#define LOG_ERROR(msg, ...) SYSLOG(msg, ##__VA_ARGS__)
#define LOG(msg, ...) SYSLOG(msg, ##__VA_ARGS__)
#endif

/* MapGuard Environment variable configurations */

/* Disallows PROT_READ, PROT_WRITE, PROT_EXEC mappings */
#define MG_DISALLOW_RWX "MG_DISALLOW_RWX"
/* Disallows RW allocations to ever transition to PROT_EXEC */
#define MG_DISALLOW_TRANSITION_TO_X "MG_DISALLOW_TRANSITION_TO_X"
/* Disallows X allocations to ever transition to PROT_WRITE */
#define MG_DISALLOW_TRANSITION_FROM_X "MG_DISALLOW_TRANSITION_FROM_X"
/* Disallows page allocations at a set address (enforces ASLR) */
#define MG_DISALLOW_STATIC_ADDRESS "MG_DISALLOW_STATIC_ADDRESS"
/* Force top and bottom guard page allocations */
#define MG_ENABLE_GUARD_PAGES "MG_ENABLE_GUARD_PAGES"
/* Abort the process when security policies are violated */
#define MG_PANIC_ON_VIOLATION "MG_PANIC_ON_VIOLATION"
/* Fill all allocated pages with a byte pattern 0xde */
#define MG_POISON_ON_ALLOCATION "MG_POISON_ON_ALLOCATION"
/* Enable the mapping cache, required for guard page allocation */
#define MG_USE_MAPPING_CACHE "MG_USE_MAPPING_CACHE"
/* Enable telemetry via syslog */
#define MG_ENABLE_SYSLOG "MG_ENABLE_SYSLOG"

#define ENV_TO_INT(env, config) \
    if(env_to_int(env)) {       \
        config = 1;             \
    }

#define MAYBE_PANIC                            \
    if(g_mapguard_policy.panic_on_violation) { \
        abort();                               \
    }

#define ROUND_UP_PAGE(N) ((((N) + (g_page_size) -1) / (g_page_size)) * (g_page_size))
#define ROUND_DOWN_PAGE(N) (ROUND_UP_PAGE(N) - g_page_size)

#define MG_POISON_BYTE 0xde

typedef struct {
    int disallow_rwx;
    int disallow_transition_to_x;
    int disallow_transition_from_x;
    int disallow_static_address;
    int enable_guard_pages;
    int panic_on_violation;
    int poison_on_allocation;
    int use_mapping_cache;
    int enable_syslog;
} mapguard_policy_t;

/* Global policy configuration object */
mapguard_policy_t g_mapguard_policy;

/* TODO - This structure is not thread safe */
typedef struct {
    void *start;
    void *guard_bottom;
    void *guard_top;
    size_t size;
    int immutable_prot;
    int current_prot;
    int cache_index;
#if MPK_SUPPORT
    int xom_enabled;
    int pkey_access_rights;
    int pkey;
#endif
} mapguard_cache_entry_t;

vector_t g_map_cache_vector;

size_t g_page_size;

inline __attribute__((always_inline)) void *get_base_page(void *addr) {
    return (void *) ((uintptr_t) addr & ~(g_page_size - 1));
}

mapguard_cache_entry_t *new_mapguard_cache_entry();
mapguard_cache_entry_t *get_cache_entry(void *addr);
void *is_mapguard_entry_cached(void *p, void *data);
void vector_pointer_free(void *p);
int32_t env_to_int(char *string);

#if MPK_SUPPORT
void *memcpy_xom(size_t allocation_size, void *src, size_t src_size);
int free_xom(void *addr, size_t length);
int32_t protect_mapping(void *addr);
int32_t unprotect_mapping(void *addr, int new_prot);
int32_t protect_segments();
int32_t unprotect_segments();
int32_t protect_code();
int32_t unprotect_code();
int (*g_real_pkey_mprotect)(void *addr, size_t len, int prot, int pkey);
int (*g_real_pkey_alloc)(unsigned int flags, unsigned int access_rights);
int (*g_real_pkey_free)(int pkey);
int (*g_real_pkey_set)(int pkey, unsigned int access_rights);
int (*g_real_pkey_get)(int pkey);
#endif

/* Hooked libc functions */
void *(*g_real_mmap)(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int (*g_real_munmap)(void *addr, size_t length);
int (*g_real_mprotect)(void *addr, size_t len, int prot);
void *(*g_real_mremap)(void *__addr, size_t __old_len, size_t __new_len, int __flags, ...);
