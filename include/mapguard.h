/* MapGuard - Copyright Chris Rohlf - 2025 */
#pragma once
#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <link.h>
#include <linux/random.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>

#if THREAD_SUPPORT
#include <pthread.h>
#endif

#include <syslog.h>
#include <unistd.h>

#define OK 0
#define ERROR -1
#define GUARD_PAGE_COUNT 2

/* Keep ALL existing LOG macros exactly as they are */
#if DEBUG
#define LOG_ERROR(msg, ...) \
    fprintf(stderr, "[LOG][%d](%s) (%s) - " msg "\n", getpid(), __FUNCTION__, strerror(errno), ##__VA_ARGS__); \
    fflush(stderr);

#define LOG(msg, ...) \
    fprintf(stdout, "[LOG][%d](%s) " msg "\n", getpid(), __FUNCTION__, ##__VA_ARGS__); \
    fflush(stdout);
#else
#define LOG_ERROR(msg, ...) SYSLOG(msg, ##__VA_ARGS__)
#define LOG(msg, ...) SYSLOG(msg, ##__VA_ARGS__)
#endif

#define LOG_AND_ABORT(msg, ...) \
    fprintf(stderr, "[LOG][%d](%s) (%s) - " msg "\n", getpid(), __FUNCTION__, strerror(errno), ##__VA_ARGS__); \
    fflush(stderr); \
    abort();

#define SYSLOG(msg, ...) \
    if(g_mapguard_policy.enable_syslog) { \
        syslog(LOG_ALERT, msg, ##__VA_ARGS__); \
    }

/* Keep ALL existing environment variable defines */
#define MG_PREVENT_RWX "MG_PREVENT_RWX"
#define MG_PREVENT_TRANSITION_TO_X "MG_PREVENT_TRANSITION_TO_X"
#define MG_PREVENT_TRANSITION_FROM_X "MG_PREVENT_TRANSITION_FROM_X"
#define MG_PREVENT_STATIC_ADDRESS "MG_PREVENT_STATIC_ADDRESS"
#define MG_ENABLE_GUARD_PAGES "MG_ENABLE_GUARD_PAGES"
#define MG_PANIC_ON_VIOLATION "MG_PANIC_ON_VIOLATION"
#define MG_POISON_ON_ALLOCATION "MG_POISON_ON_ALLOCATION"
#define MG_USE_MAPPING_CACHE "MG_USE_MAPPING_CACHE"
#define MG_ENABLE_SYSLOG "MG_ENABLE_SYSLOG"

#define ENV_TO_INT(env, config) \
    if(env_to_int(env)) { \
        config = 1; \
    }

#define MAYBE_PANIC() \
    if(g_mapguard_policy.panic_on_violation) { \
        abort(); \
    }

#define ROUND_UP_PAGE(N) (((N) + g_page_size - 1) & ~(g_page_size - 1))
#define ROUND_DOWN_PAGE(N) ((N) & ~(g_page_size - 1))

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

extern pthread_mutex_t _mg_mutex;

#if THREAD_SUPPORT
#define LOCK_MG() pthread_mutex_lock(&_mg_mutex);
#define UNLOCK_MG() pthread_mutex_unlock(&_mg_mutex);
#else
#define LOCK_MG()
#define UNLOCK_MG()
#endif

#define MG_POISON_BYTE 0xde

/* Keep original policy struct exactly */
typedef struct {
    uint8_t prevent_rwx;
    uint8_t prevent_transition_to_x;
    uint8_t prevent_transition_from_x;
    uint8_t prevent_static_address;
    uint8_t prevent_policies_enabled;
    uint8_t enable_guard_pages;
    uint8_t panic_on_violation;
    uint8_t poison_on_allocation;
    uint8_t use_mapping_cache;
    uint8_t actions_enabled;
    uint8_t enable_syslog;
} mapguard_policy_t;

extern mapguard_policy_t g_mapguard_policy;

/* Keep original cache metadata struct exactly */
typedef struct {
    void *next;
    bool full;
    uint32_t total;
    uint32_t free;
} mapguard_cache_metadata_t;

/* Keep original cache entry struct - add alloc_ts and call_site fields */
typedef struct mapguard_cache_entry {
    void *start;
    uint16_t idx;
    size_t size;
    uint64_t alloc_ts;      /* allocation timestamp (ns monotonic) */
    uintptr_t call_site;    /* return address of caller */
    bool guarded_b;
    bool guarded_t;
    int32_t immutable_prot;
    int32_t current_prot;
    struct mapguard_cache_entry *hash_next;
} mapguard_cache_entry_t;

/* ===== LEAK TRACKER (independent of security cache) ===== */

#define MG_LEAK_POOL_SIZE 8192
#define MG_LEAK_HASH_SIZE 4096
#define MG_LEAK_HASH(addr) (((uintptr_t)(addr) >> 12) & (MG_LEAK_HASH_SIZE - 1))

typedef struct mg_leak_entry {
    void *addr;                    /* start address of mapping */
    size_t size;                   /* size in bytes */
    uint64_t alloc_ts;             /* allocation timestamp (ns monotonic) */
    uintptr_t call_site;           /* return address of caller */
    bool in_use;                   /* whether this pool slot is active */
    struct mg_leak_entry *next;    /* linked list for iteration */
    struct mg_leak_entry *prev;    /* doubly linked list */
    struct mg_leak_entry *hash_next; /* hash bucket chain */
} mg_leak_entry_t;

/* Snapshot ring buffer for growth detection */
#define MG_MAX_SNAPSHOTS 64

typedef struct {
    uint64_t current_bytes;              /* current total mapped bytes */
    uint64_t peak_bytes;                 /* peak total mapped bytes */
    uint64_t total_allocs;               /* total mmap calls tracked */
    uint64_t outstanding;                /* current outstanding mapping count */
    uint64_t snap_bytes[MG_MAX_SNAPSHOTS]; /* snapshot ring buffer: bytes */
    uint64_t snap_ts[MG_MAX_SNAPSHOTS];    /* snapshot ring buffer: timestamps */
    size_t snap_write_idx;               /* next write position in ring */
    size_t valid_snapshots;              /* how many valid snapshots we have */
    bool growth_warning_issued;          /* prevent repeated warnings */
    bool pool_exhausted;                 /* tracking pool ran out */
} mg_tracker_stats_t;

/* ===== FUNCTION PROTOTYPES ===== */

/* Original functions */
mapguard_cache_metadata_t *new_mce_page();
mapguard_cache_entry_t *find_free_mce();
mapguard_cache_entry_t *get_cache_entry(void *addr);
int32_t env_to_int(char *string);
uint64_t rand_uint64(void);
void *allocate_guard_page(void *p);
void make_guard_page(void *p);
void unmap_guard_pages(mapguard_cache_entry_t *mce);
void cache_entry_insert(mapguard_cache_entry_t *mce);
void cache_entry_remove(mapguard_cache_entry_t *mce);

/* Leak tracker functions */
void mg_tracker_init(void);
void mg_tracker_record_alloc(void *addr, size_t size, uintptr_t call_site);
void mg_tracker_record_free(void *addr, size_t size);
void mg_tracker_record_partial_free(void *addr, size_t free_size, void *remaining_addr, size_t remaining_size);
void mg_tracker_record_split(void *orig_addr, void *lower_addr, size_t lower_size, void *upper_addr, size_t upper_size, uint64_t orig_ts, uintptr_t orig_site);
void mg_tracker_record_remap(void *old_addr, void *new_addr, size_t old_size, size_t new_size);
void mg_tracker_take_snapshot(void);
bool mg_tracker_check_growth(void);
void mg_tracker_generate_report(void);

/* Snapshot thread */
void mg_snapshot_thread_start(void);
void mg_snapshot_thread_stop(void);

/* Timestamp helper */
static inline uint64_t mg_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
