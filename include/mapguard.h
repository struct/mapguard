/* MapGuard - Copyright Chris Rohlf - 2025 */
#pragma once
#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <link.h>
#include <linux/random.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#if THREAD_SUPPORT
#include <pthread.h>
#endif

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

#define LOG_AND_ABORT(msg, ...)                                                                                 \
    fprintf(stderr, "[LOG][%d](%s) (%s) - " msg "\n", getpid(), __FUNCTION__, strerror(errno), ##__VA_ARGS__);  \
    fflush(stderr);                                                                                             \
    abort();

/* MapGuard Environment variable configurations */

/* Prevent PROT_READ, PROT_WRITE, PROT_EXEC mappings */
#define MG_PREVENT_RWX "MG_PREVENT_RWX"
/* Prevent RW- allocations to ever transition to PROT_EXEC */
#define MG_PREVENT_TRANSITION_TO_X "MG_PREVENT_TRANSITION_TO_X"
/* Prevent R-X allocations to ever transition to PROT_WRITE */
#define MG_PREVENT_TRANSITION_FROM_X "MG_PREVENT_TRANSITION_FROM_X"
/* Prevent page allocations at a set address (enforces ASLR) */
#define MG_PREVENT_STATIC_ADDRESS "MG_PREVENT_STATIC_ADDRESS"
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

#define MAYBE_PANIC()                          \
    if(g_mapguard_policy.panic_on_violation) { \
        abort();                               \
    }

#define ROUND_UP_PAGE(N) (((N) + g_page_size - 1) & ~(g_page_size - 1))
#define ROUND_DOWN_PAGE(N) ((N) & ~(g_page_size - 1))

/* Branch prediction hints for hot paths */
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

/* Skip cache for very large allocations (more than this many pages) */
#define LARGE_ALLOCATION_THRESHOLD (16 * g_page_size)

extern pthread_mutex_t _mg_mutex;

#if THREAD_SUPPORT
#define LOCK_MG() \
    pthread_mutex_lock(&_mg_mutex);

#define UNLOCK_MG() \
    pthread_mutex_unlock(&_mg_mutex);
#else
#define LOCK_MG()
#define UNLOCK_MG()
#endif

#define MG_POISON_BYTE 0xde

typedef struct {
    uint8_t prevent_rwx;
    uint8_t prevent_transition_to_x;
    uint8_t prevent_transition_from_x;
    uint8_t prevent_static_address;
    uint8_t enable_guard_pages;
    uint8_t panic_on_violation;
    uint8_t poison_on_allocation;
    uint8_t use_mapping_cache;
    uint8_t enable_syslog;
} mapguard_policy_t;

extern size_t g_page_size;

typedef struct {
    void *next; /* Points to the page of [mapguard_cache_metadata_t ... mapguard_cache_entry_t ... n] */
    bool full;
    uint32_t total;
    uint32_t free;
} mapguard_cache_metadata_t;

/* TODO - This structure is not thread safe */
typedef struct {
    void *start;
    /* Tracks which entry this is, uint16_t because pages could be 16k */
    uint16_t idx;
    size_t size;
    bool guarded_b;
    bool guarded_t;
    int32_t immutable_prot;
    int32_t current_prot;
    int32_t cache_index;
#if MPK_SUPPORT
    int32_t xom_enabled;
    int32_t pkey_access_rights;
    int32_t pkey;
#endif
} mapguard_cache_entry_t;

inline __attribute__((always_inline)) void *get_base_page(void *addr) {
    return (void *) ((uintptr_t) addr & ~(g_page_size - 1));
}

mapguard_cache_metadata_t *new_mce_page();
mapguard_cache_entry_t *find_free_mce();
mapguard_cache_entry_t *get_cache_entry(void *addr);
void *is_mapguard_entry_cached(void *p, void *data);
void vector_pointer_free(void *p);
int32_t env_to_int(char *string);
uint64_t rand_uint64(void);
void mark_guard_page(void *p);
void *allocate_guard_page(void *p);
void make_guard_page(void *p);

#if MPK_SUPPORT
void *memcpy_xom(size_t allocation_size, void *src, size_t src_size);
int free_xom(void *addr, size_t length);
int32_t protect_mapping(void *addr);
int32_t unprotect_mapping(void *addr, int new_prot);
int32_t protect_segments();
int32_t unprotect_segments();
int32_t protect_code();
int32_t unprotect_code();
uint64_t rand_uint64(void);
#endif
