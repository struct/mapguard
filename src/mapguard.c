/* MapGuard - Copyright Chris Rohlf - 2025 */

#include "mapguard.h"

/* ===== Thread-local recursion guard =====
 * Prevents MapGuard's own internal mmap/munmap calls (e.g. for MCE pages,
 * guard pages) from being recorded in the leak tracker. */
static __thread int mg_internal = 0;

/* ===== Original MapGuard security mutex ===== */
pthread_mutex_t _mg_mutex;

/* ===== Dedicated leak-tracker mutex (separate from security mutex) ===== */
static pthread_mutex_t _mg_leak_mutex = PTHREAD_MUTEX_INITIALIZER;

#define LOCK_LEAK()   pthread_mutex_lock(&_mg_leak_mutex)
#define UNLOCK_LEAK() pthread_mutex_unlock(&_mg_leak_mutex)

/* ===== Static preallocated leak-tracking pool ===== */
static mg_leak_entry_t leak_pool[MG_LEAK_POOL_SIZE];
static mg_leak_entry_t *leak_hash_table[MG_LEAK_HASH_SIZE];
static mg_leak_entry_t *leak_list_head = NULL;
static mg_leak_entry_t *leak_list_tail = NULL;
static size_t leak_pool_used = 0;

/* ===== Tracker statistics ===== */
static mg_tracker_stats_t g_stats = {0};

/* ===== Configuration (loaded from environment) ===== */
static unsigned int mg_snapshot_interval_ms = 5000;       /* default 5 seconds */
static unsigned int mg_observe_count = 5;                  /* snapshots needed for growth check */
static uint64_t mg_growth_threshold_bytes = 1048576;       /* 1 MiB default */

/* ===== Snapshot background thread ===== */
static pthread_t snapshot_tid;
static volatile int snapshot_thread_running = 0;

/* ===== Original MapGuard globals ===== */
mapguard_cache_metadata_t *mce_head;

#define HASH_TABLE_SIZE 16384
#define HASH_ADDR(addr) (((uintptr_t)(addr) >> 12) & (HASH_TABLE_SIZE - 1))

mapguard_cache_entry_t *g_hash_table[HASH_TABLE_SIZE];

static size_t g_page_size;
static uint32_t g_page_shift;

mapguard_policy_t g_mapguard_policy;

/* Pointers to hooked libc functions */
void *(*g_real_mmap)(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int (*g_real_munmap)(void *addr, size_t length);
int (*g_real_mprotect)(void *addr, size_t len, int prot);
void *(*g_real_mremap)(void *__addr, size_t __old_len, size_t __new_len, int __flags, ...);

/* ===================================================================
 * LEAK TRACKER IMPLEMENTATION (independent of security cache)
 * =================================================================== */

/* Allocate a leak entry from the static pool. Returns NULL if exhausted. */
static mg_leak_entry_t *leak_pool_alloc(void) {
    /* Caller must hold _mg_leak_mutex */
    if(leak_pool_used >= MG_LEAK_POOL_SIZE) {
        if(!g_stats.pool_exhausted) {
            g_stats.pool_exhausted = true;
            fprintf(stderr, "[MapGuard] WARNING: leak-tracking pool exhausted (%d entries). "
                    "Further allocations will not be tracked.\n", MG_LEAK_POOL_SIZE);
        }
        return NULL;
    }
    mg_leak_entry_t *e = &leak_pool[leak_pool_used++];
    memset(e, 0, sizeof(*e));
    e->in_use = true;
    return e;
}

/* Insert a leak entry into hash table and doubly-linked list */
static void leak_insert(mg_leak_entry_t *e) {
    /* Caller must hold _mg_leak_mutex */
    uint32_t bucket = MG_LEAK_HASH(e->addr);
    e->hash_next = leak_hash_table[bucket];
    leak_hash_table[bucket] = e;

    /* Append to doubly-linked list */
    e->next = NULL;
    e->prev = leak_list_tail;
    if(leak_list_tail) {
        leak_list_tail->next = e;
    } else {
        leak_list_head = e;
    }
    leak_list_tail = e;
}

/* Find a leak entry by address */
static mg_leak_entry_t *leak_find(void *addr) {
    /* Caller must hold _mg_leak_mutex */
    uint32_t bucket = MG_LEAK_HASH(addr);
    mg_leak_entry_t *e = leak_hash_table[bucket];
    while(e) {
        if(e->in_use && e->addr == addr) {
            return e;
        }
        e = e->hash_next;
    }
    return NULL;
}

/* Remove a leak entry from hash table and linked list.
 * Note: we mark it as not in_use but don't reclaim the pool slot
 * (static pool, slots are not reused to keep it simple and safe). */
static void leak_remove(mg_leak_entry_t *e) {
    /* Caller must hold _mg_leak_mutex */
    /* Remove from hash table */
    uint32_t bucket = MG_LEAK_HASH(e->addr);
    mg_leak_entry_t *cur = leak_hash_table[bucket];
    mg_leak_entry_t *prev = NULL;
    while(cur) {
        if(cur == e) {
            if(prev) {
                prev->hash_next = cur->hash_next;
            } else {
                leak_hash_table[bucket] = cur->hash_next;
            }
            break;
        }
        prev = cur;
        cur = cur->hash_next;
    }

    /* Remove from doubly-linked list */
    if(e->prev) {
        e->prev->next = e->next;
    } else {
        leak_list_head = e->next;
    }
    if(e->next) {
        e->next->prev = e->prev;
    } else {
        leak_list_tail = e->prev;
    }

    e->in_use = false;
    e->next = NULL;
    e->prev = NULL;
    e->hash_next = NULL;
}

/* ===== Public tracker API ===== */

void mg_tracker_init(void) {
    memset(leak_pool, 0, sizeof(leak_pool));
    memset(leak_hash_table, 0, sizeof(leak_hash_table));
    leak_list_head = NULL;
    leak_list_tail = NULL;
    leak_pool_used = 0;
    memset(&g_stats, 0, sizeof(g_stats));
    pthread_mutex_init(&_mg_leak_mutex, NULL);
}

void mg_tracker_record_alloc(void *addr, size_t size, uintptr_t call_site) {
    LOCK_LEAK();
    mg_leak_entry_t *e = leak_pool_alloc();
    if(e) {
        e->addr = addr;
        e->size = size;
        e->alloc_ts = mg_now_ns();
        e->call_site = call_site;
        leak_insert(e);

        g_stats.current_bytes += size;
        g_stats.total_allocs++;
        g_stats.outstanding++;
        if(g_stats.current_bytes > g_stats.peak_bytes) {
            g_stats.peak_bytes = g_stats.current_bytes;
        }
    }
    UNLOCK_LEAK();
}

void mg_tracker_record_free(void *addr, size_t size) {
    LOCK_LEAK();
    mg_leak_entry_t *e = leak_find(addr);
    if(e) {
        if(g_stats.current_bytes >= e->size) {
            g_stats.current_bytes -= e->size;
        } else {
            g_stats.current_bytes = 0;
        }
        if(g_stats.outstanding > 0) {
            g_stats.outstanding--;
        }
        leak_remove(e);
    }
    UNLOCK_LEAK();
}

/* Handle partial munmap from beginning or end: update entry in place */
void mg_tracker_record_partial_free(void *addr, size_t free_size,
                                     void *remaining_addr, size_t remaining_size) {
    LOCK_LEAK();
    mg_leak_entry_t *e = leak_find(addr);
    if(e) {
        /* Remove old entry from hash (address is changing) */
        leak_remove(e);
        /* Update with remaining portion */
        e->in_use = true;
        e->addr = remaining_addr;
        e->size = remaining_size;
        /* Preserve original alloc_ts and call_site */
        leak_insert(e);

        if(g_stats.current_bytes >= free_size) {
            g_stats.current_bytes -= free_size;
        } else {
            g_stats.current_bytes = 0;
        }
        if(g_stats.current_bytes > g_stats.peak_bytes) {
            g_stats.peak_bytes = g_stats.current_bytes;
        }
    }
    UNLOCK_LEAK();
}

/* Handle split (middle unmap): original becomes lower, new entry for upper */
void mg_tracker_record_split(void *orig_addr,
                              void *lower_addr, size_t lower_size,
                              void *upper_addr, size_t upper_size,
                              uint64_t orig_ts, uintptr_t orig_site) {
    LOCK_LEAK();
    mg_leak_entry_t *e = leak_find(orig_addr);
    size_t freed_bytes = 0;
    if(e) {
        freed_bytes = e->size - lower_size - upper_size;
        /* Update original entry to be the lower portion */
        leak_remove(e);
        e->in_use = true;
        e->addr = lower_addr;
        e->size = lower_size;
        leak_insert(e);
    }

    /* Allocate new entry for upper portion */
    mg_leak_entry_t *upper = leak_pool_alloc();
    if(upper) {
        upper->addr = upper_addr;
        upper->size = upper_size;
        upper->alloc_ts = orig_ts;
        upper->call_site = orig_site;
        leak_insert(upper);

        g_stats.outstanding++;  /* One more entry (split creates two from one) */
    } else {
        fprintf(stderr, "[MapGuard] WARNING: leak-tracking pool exhausted during split\n");
    }

    /* Adjust byte count for freed middle portion */
    if(g_stats.current_bytes >= freed_bytes) {
        g_stats.current_bytes -= freed_bytes;
    } else {
        g_stats.current_bytes = 0;
    }
    UNLOCK_LEAK();
}

/* Handle mremap: remove old entry, create new with preserved metadata */
void mg_tracker_record_remap(void *old_addr, void *new_addr,
                              size_t old_size, size_t new_size) {
    LOCK_LEAK();
    mg_leak_entry_t *e = leak_find(old_addr);
    uint64_t preserved_ts = mg_now_ns();
    uintptr_t preserved_site = 0;

    if(e) {
        preserved_ts = e->alloc_ts;
        preserved_site = e->call_site;
        /* Remove old stats */
        if(g_stats.current_bytes >= e->size) {
            g_stats.current_bytes -= e->size;
        } else {
            g_stats.current_bytes = 0;
        }
        if(g_stats.outstanding > 0) {
            g_stats.outstanding--;
        }
        leak_remove(e);
    }

    /* Create new entry with preserved timestamp and call site */
    mg_leak_entry_t *ne = leak_pool_alloc();
    if(ne) {
        ne->addr = new_addr;
        ne->size = new_size;
        ne->alloc_ts = preserved_ts;
        ne->call_site = preserved_site;
        leak_insert(ne);

        g_stats.current_bytes += new_size;
        g_stats.outstanding++;
        if(g_stats.current_bytes > g_stats.peak_bytes) {
            g_stats.peak_bytes = g_stats.current_bytes;
        }
    } else {
        fprintf(stderr, "[MapGuard] WARNING: leak-tracking pool exhausted in mremap\n");
    }
    UNLOCK_LEAK();
}

/* Take a snapshot of current memory usage for growth detection */
void mg_tracker_take_snapshot(void) {
    LOCK_LEAK();
    size_t idx = g_stats.snap_write_idx % MG_MAX_SNAPSHOTS;
    g_stats.snap_bytes[idx] = g_stats.current_bytes;
    g_stats.snap_ts[idx] = mg_now_ns();
    g_stats.snap_write_idx++;
    if(g_stats.valid_snapshots < MG_MAX_SNAPSHOTS) {
        g_stats.valid_snapshots++;
    }
    UNLOCK_LEAK();
}

/* Check for sustained growth. Returns true if growth exceeds threshold.
 * Only checks when we have enough valid snapshots (>= mg_observe_count).
 * Prevents repeated warnings for the same growth event. */
bool mg_tracker_check_growth(void) {
    LOCK_LEAK();
    bool result = false;

    if(g_stats.valid_snapshots >= mg_observe_count && !g_stats.growth_warning_issued) {
        /* Find oldest and newest valid snapshots */
        size_t newest_idx = (g_stats.snap_write_idx - 1) % MG_MAX_SNAPSHOTS;
        size_t oldest_idx;
        if(g_stats.valid_snapshots >= MG_MAX_SNAPSHOTS) {
            oldest_idx = g_stats.snap_write_idx % MG_MAX_SNAPSHOTS;
        } else {
            oldest_idx = 0;
        }

        uint64_t oldest_bytes = g_stats.snap_bytes[oldest_idx];
        uint64_t newest_bytes = g_stats.snap_bytes[newest_idx];

        if(newest_bytes > oldest_bytes &&
           (newest_bytes - oldest_bytes) >= mg_growth_threshold_bytes) {
            result = true;
            g_stats.growth_warning_issued = true;
        }
    }

    UNLOCK_LEAK();
    return result;
}

/* Generate final plain-text report */
void mg_tracker_generate_report(void) {
    char *report_path = getenv("MG_REPORT_PATH");
    char default_path[512];
    if(!report_path || report_path[0] == '\0') {
        char *home = getenv("HOME");
        if(home) {
            snprintf(default_path, sizeof(default_path), "%s/mg_report.txt", home);
        } else {
            snprintf(default_path, sizeof(default_path), "/tmp/mg_report.txt");
        }
        report_path = default_path;
    }

    /* Collect data under lock, write file without lock */
    LOCK_LEAK();

    /* Count outstanding entries and snapshot data */
    uint64_t current_bytes = g_stats.current_bytes;
    uint64_t peak_bytes = g_stats.peak_bytes;
    uint64_t total_allocs = g_stats.total_allocs;
    uint64_t outstanding = g_stats.outstanding;
    bool pool_exhausted = g_stats.pool_exhausted;
    bool growth_detected = g_stats.growth_warning_issued;
    size_t valid_snaps = g_stats.valid_snapshots;

    /* Collect growth info */
    uint64_t growth_oldest = 0, growth_newest = 0;
    uint64_t growth_oldest_ts = 0, growth_newest_ts = 0;
    if(valid_snaps >= mg_observe_count) {
        size_t newest_idx = (g_stats.snap_write_idx - 1) % MG_MAX_SNAPSHOTS;
        size_t oldest_idx;
        if(valid_snaps >= MG_MAX_SNAPSHOTS) {
            oldest_idx = g_stats.snap_write_idx % MG_MAX_SNAPSHOTS;
        } else {
            oldest_idx = 0;
        }
        growth_oldest = g_stats.snap_bytes[oldest_idx];
        growth_newest = g_stats.snap_bytes[newest_idx];
        growth_oldest_ts = g_stats.snap_ts[oldest_idx];
        growth_newest_ts = g_stats.snap_ts[newest_idx];
    }

    /* Build a local copy of outstanding entries for report */
    typedef struct {
        void *addr;
        size_t size;
        uint64_t alloc_ts;
        uintptr_t call_site;
    } report_entry_t;

    /* Use a fixed-size buffer on stack (limited to 256 entries for report) */
    #define MAX_REPORT_ENTRIES 256
    report_entry_t entries[MAX_REPORT_ENTRIES];
    size_t entry_count = 0;

    uint64_t now = mg_now_ns();
    mg_leak_entry_t *cur = leak_list_head;
    while(cur && entry_count < MAX_REPORT_ENTRIES) {
        if(cur->in_use) {
            entries[entry_count].addr = cur->addr;
            entries[entry_count].size = cur->size;
            entries[entry_count].alloc_ts = cur->alloc_ts;
            entries[entry_count].call_site = cur->call_site;
            entry_count++;
        }
        cur = cur->next;
    }

    UNLOCK_LEAK();

    /* Now write report without holding any lock */
    FILE *fp = fopen(report_path, "w");
    if(!fp) {
        fprintf(stderr, "[MapGuard] ERROR: cannot open report file: %s\n", report_path);
        return;
    }

    fprintf(fp, "=======================================================\n");
    fprintf(fp, "         MapGuard Memory Leak Detection Report\n");
    fprintf(fp, "=======================================================\n\n");

    fprintf(fp, "--- Summary ---\n");
    fprintf(fp, "  Total allocations tracked:  %lu\n", (unsigned long)total_allocs);
    fprintf(fp, "  Outstanding mappings:       %lu\n", (unsigned long)outstanding);
    fprintf(fp, "  Current mapped bytes:       %lu\n", (unsigned long)current_bytes);
    fprintf(fp, "  Peak mapped bytes:          %lu\n", (unsigned long)peak_bytes);
    fprintf(fp, "  Snapshots collected:        %zu\n", valid_snaps);
    if(pool_exhausted) {
        fprintf(fp, "\n  *** WARNING: Tracking pool exhausted (max %d entries). ***\n"
                    "  *** Some allocations may not have been tracked.       ***\n",
                MG_LEAK_POOL_SIZE);
    }
    fprintf(fp, "\n");

    /* Growth detection */
    fprintf(fp, "--- Growth Detection ---\n");
    if(valid_snaps < mg_observe_count) {
        fprintf(fp, "  Insufficient snapshots for growth detection (%zu < %u required)\n",
                valid_snaps, mg_observe_count);
    } else if(growth_detected) {
        double oldest_sec = (double)growth_oldest_ts / 1e9;
        double newest_sec = (double)growth_newest_ts / 1e9;
        fprintf(fp, "  *** GROWTH WARNING ***\n");
        fprintf(fp, "  Memory grew from %lu bytes to %lu bytes\n",
                (unsigned long)growth_oldest, (unsigned long)growth_newest);
        fprintf(fp, "  Growth: %lu bytes (threshold: %lu bytes)\n",
                (unsigned long)(growth_newest - growth_oldest),
                (unsigned long)mg_growth_threshold_bytes);
        fprintf(fp, "  Observation window: %.3f s to %.3f s (monotonic)\n",
                oldest_sec, newest_sec);
    } else {
        fprintf(fp, "  No sustained growth detected (threshold: %lu bytes)\n",
                (unsigned long)mg_growth_threshold_bytes);
    }
    fprintf(fp, "\n");

    /* Outstanding mappings */
    fprintf(fp, "--- Outstanding Application Mappings (%zu) ---\n", entry_count);
    if(entry_count == 0) {
        fprintf(fp, "  (none - all mappings were properly freed)\n");
    } else {
        fprintf(fp, "  %-4s  %-18s  %-12s  %-12s  %-18s\n",
                "#", "Address", "Size (B)", "Age (sec)", "Call Site");
        fprintf(fp, "  %-4s  %-18s  %-12s  %-12s  %-18s\n",
                "----", "------------------", "------------", "------------", "------------------");
        for(size_t i = 0; i < entry_count; i++) {
            double age_sec = (double)(now - entries[i].alloc_ts) / 1e9;
            fprintf(fp, "  %-4zu  0x%-16lx  %-12zu  %-12.3f  0x%-16lx\n",
                    i + 1,
                    (unsigned long)(uintptr_t)entries[i].addr,
                    entries[i].size,
                    age_sec,
                    (unsigned long)entries[i].call_site);
        }
    }
    if(entry_count >= MAX_REPORT_ENTRIES && outstanding > MAX_REPORT_ENTRIES) {
        fprintf(fp, "\n  (report truncated to %d entries, %lu total outstanding)\n",
                MAX_REPORT_ENTRIES, (unsigned long)outstanding);
    }

    fprintf(fp, "\n=======================================================\n");
    fprintf(fp, "  Note: Only application mappings are shown above.\n");
    fprintf(fp, "  Internal MapGuard allocations (guard pages, cache\n");
    fprintf(fp, "  pages) are excluded from this report.\n");
    fprintf(fp, "=======================================================\n");

    fclose(fp);
    fprintf(stderr, "[MapGuard] Report written to: %s\n", report_path);
}

/* ===== Snapshot thread ===== */
static void *snapshot_thread_func(void *arg) {
    (void)arg;
    while(snapshot_thread_running) {
        /* Sleep for the configured interval */
        usleep(mg_snapshot_interval_ms * 1000);
        if(!snapshot_thread_running) break;
        mg_tracker_take_snapshot();

        /* Check growth and log warning */
        if(mg_tracker_check_growth()) {
            fprintf(stderr, "[MapGuard] GROWTH WARNING: Memory usage increased by >= %lu bytes "
                    "over %u observation(s)\n",
                    (unsigned long)mg_growth_threshold_bytes, mg_observe_count);
        }
    }
    return NULL;
}

void mg_snapshot_thread_start(void) {
    snapshot_thread_running = 1;
    if(pthread_create(&snapshot_tid, NULL, snapshot_thread_func, NULL) != 0) {
        fprintf(stderr, "[MapGuard] WARNING: failed to start snapshot thread\n");
        snapshot_thread_running = 0;
    }
}

void mg_snapshot_thread_stop(void) {
    if(snapshot_thread_running) {
        snapshot_thread_running = 0;
        pthread_join(snapshot_tid, NULL);
    }
}

/* ===================================================================
 * ORIGINAL MAPGUARD FUNCTIONS (preserved)
 * =================================================================== */

mapguard_cache_metadata_t *new_mce_page() {
    uint64_t hint = ROUND_DOWN_PAGE(rand_uint64());
    hint &= 0x3FFFFFFFF000;

    mg_internal = 1;
    void *ptr = g_real_mmap((void *)hint, g_page_size * 3, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    mg_internal = 0;

    if(ptr == MAP_FAILED) {
        LOG_AND_ABORT("mmap failed in new_mce_page");
        abort();
    }

    mg_internal = 1;
    make_guard_page((void *)ptr);
    make_guard_page((void *)ptr + (g_page_size * 2));
    mg_internal = 0;

    mapguard_cache_metadata_t *t = (mapguard_cache_metadata_t *)(ptr + g_page_size);
    t->total = (g_page_size - sizeof(mapguard_cache_metadata_t)) / sizeof(mapguard_cache_entry_t);
    t->free = t->total;
    t->next = NULL;
    return t;
}

void *allocate_guard_page(void *p) {
    mg_internal = 1;
    void *result = g_real_mmap(p, g_page_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    mg_internal = 0;
    return result;
}

void make_guard_page(void *p) {
    mg_internal = 1;
    g_real_mprotect(p, g_page_size, PROT_NONE);
    madvise(p, g_page_size, MADV_DONTNEED);
    mg_internal = 0;
    LOG("Mapped guard page %p", p);
}

void unmap_top_guard_page(mapguard_cache_entry_t *mce) {
#if DEBUG
    if(mce->guarded_t == false) {
        LOG_AND_ABORT("Attempting to unmap missing top guard page")
    }
#endif
    mg_internal = 1;
    g_real_munmap(mce->start + mce->size, g_page_size);
    mg_internal = 0;
    mce->guarded_t = false;
    LOG("Unmapped top guard page %p", mce->start + mce->size);
}

void unmap_bottom_guard_page(mapguard_cache_entry_t *mce) {
#if DEBUG
    if(mce->guarded_b == false) {
        LOG_AND_ABORT("Attempting to unmap missing bottom guard page")
    }
#endif
    mg_internal = 1;
    g_real_munmap(mce->start - g_page_size, g_page_size);
    mg_internal = 0;
    mce->guarded_b = false;
    LOG("Unmapped bottom guard page %p", mce->start - g_page_size);
}

void unmap_guard_pages(mapguard_cache_entry_t *mce) {
    if(NULL == mce) {
        LOG_AND_ABORT("This should never happen: mce == NULL");
    }
    if(mce->guarded_b) {
        unmap_bottom_guard_page(mce);
    }
    if(mce->guarded_t) {
        unmap_top_guard_page(mce);
    }
}

void map_bottom_guard_page(mapguard_cache_entry_t *mce) {
    make_guard_page(mce->start - g_page_size);
    mce->guarded_b = true;
}

void map_top_guard_page(mapguard_cache_entry_t *mce) {
    make_guard_page(mce->start + mce->size);
    mce->guarded_t = true;
}

void mark_guard_pages(mapguard_cache_entry_t *mce) {
    map_bottom_guard_page(mce);
    map_top_guard_page(mce);
}

mapguard_cache_entry_t *find_free_mce() {
    mapguard_cache_metadata_t *current = mce_head;
    mapguard_cache_metadata_t *previous = NULL;

    while(current) {
        if(current->free) {
            mapguard_cache_entry_t *entries = (mapguard_cache_entry_t *)((uint8_t *)current + sizeof(mapguard_cache_metadata_t));
            for(uint32_t i = 0; i < current->total; i++) {
                mapguard_cache_entry_t *candidate = entries + i;
                if(candidate->start == NULL) {
                    current->free--;
                    return candidate;
                }
            }
            current->free = 0;
        }
        previous = current;
        current = current->next;
    }

    mapguard_cache_metadata_t *new_page = new_mce_page();
    if(previous) {
        previous->next = new_page;
    } else {
        mce_head = new_page;
    }
    new_page->free--;
    return (mapguard_cache_entry_t *)((uint8_t *)new_page + sizeof(mapguard_cache_metadata_t));
}

uint64_t rand_uint64(void) {
    uint64_t val = 0;
    syscall(SYS_getrandom, &val, sizeof(val), GRND_NONBLOCK);
    return val;
}

int32_t env_to_int(char *string) {
    char *p = getenv(string);
    if(p == NULL) {
        return 0;
    }
    char *endptr;
    errno = 0;
    unsigned long val = strtoul(p, &endptr, 0);
    if(errno != 0 || *endptr != '\0' || val > INT32_MAX) {
        return 0;
    }
    return (int32_t)val;
}

mapguard_cache_entry_t *get_cache_entry(void *addr) {
    void *page_addr = (void *)ROUND_DOWN_PAGE((uintptr_t)addr);
    uint32_t bucket = HASH_ADDR(page_addr);
    mapguard_cache_entry_t *mce = g_hash_table[bucket];

    while(mce != NULL) {
        if(addr >= mce->start && addr < (mce->start + mce->size)) {
            return mce;
        }
        mce = mce->hash_next;
    }

    for(uint32_t i = 1; i < 256; i++) {
        void *probe_addr = page_addr - (i << g_page_shift);
        uint32_t probe_bucket = HASH_ADDR(probe_addr);
        if(probe_bucket == bucket) {
            continue;
        }
        mce = g_hash_table[probe_bucket];
        while(mce != NULL) {
            if(addr >= mce->start && addr < (mce->start + mce->size)) {
                return mce;
            }
            mce = mce->hash_next;
        }
    }

    return NULL;
}

void cache_entry_insert(mapguard_cache_entry_t *mce) {
    uint32_t bucket = HASH_ADDR(mce->start);
    mce->hash_next = g_hash_table[bucket];
    g_hash_table[bucket] = mce;
}

void cache_entry_remove(mapguard_cache_entry_t *mce) {
    uint32_t bucket = HASH_ADDR(mce->start);
    mapguard_cache_entry_t *current = g_hash_table[bucket];
    mapguard_cache_entry_t *prev = NULL;

    while(current != NULL) {
        if(current == mce) {
            if(prev == NULL) {
                g_hash_table[bucket] = current->hash_next;
            } else {
                prev->hash_next = current->hash_next;
            }
            mce->hash_next = NULL;
            return;
        }
        prev = current;
        current = current->hash_next;
    }

    LOG_AND_ABORT("Failed to find cache entry to remove");
}

/* ===================================================================
 * CONSTRUCTOR / DESTRUCTOR
 * =================================================================== */

__attribute__((constructor)) void mapguard_ctor() {
    g_page_size = getpagesize();
    g_page_shift = __builtin_ctzl(g_page_size);

#if THREAD_SUPPORT
    pthread_mutex_init(&_mg_mutex, NULL);
#endif

    /* Initialize leak tracker */
    mg_tracker_init();

    /* Load leak-tracker configuration from environment */
    char *env;
    env = getenv("MG_SNAPSHOT_INTERVAL_MS");
    if(env) mg_snapshot_interval_ms = (unsigned int)atoi(env);
    env = getenv("MG_OBSERVE_COUNT");
    if(env) mg_observe_count = (unsigned int)atoi(env);
    env = getenv("MG_GROWTH_THRESHOLD_BYTES");
    if(env) mg_growth_threshold_bytes = (uint64_t)atoll(env);

    /* Enable configuration of mapguard via environment
     * variables during DSO load time only */
    ENV_TO_INT(MG_PREVENT_RWX, g_mapguard_policy.prevent_rwx);
    ENV_TO_INT(MG_PREVENT_TRANSITION_TO_X, g_mapguard_policy.prevent_transition_to_x);
    ENV_TO_INT(MG_PREVENT_TRANSITION_FROM_X, g_mapguard_policy.prevent_transition_from_x);
    ENV_TO_INT(MG_PREVENT_STATIC_ADDRESS, g_mapguard_policy.prevent_static_address);
    ENV_TO_INT(MG_ENABLE_GUARD_PAGES, g_mapguard_policy.enable_guard_pages);
    ENV_TO_INT(MG_PANIC_ON_VIOLATION, g_mapguard_policy.panic_on_violation);
    ENV_TO_INT(MG_POISON_ON_ALLOCATION, g_mapguard_policy.poison_on_allocation);
    ENV_TO_INT(MG_USE_MAPPING_CACHE, g_mapguard_policy.use_mapping_cache);
    ENV_TO_INT(MG_ENABLE_SYSLOG, g_mapguard_policy.enable_syslog);

    g_mapguard_policy.prevent_policies_enabled = g_mapguard_policy.prevent_rwx ||
                                                 g_mapguard_policy.prevent_transition_to_x ||
                                                 g_mapguard_policy.prevent_transition_from_x ||
                                                 g_mapguard_policy.prevent_static_address;

    g_mapguard_policy.actions_enabled = g_mapguard_policy.enable_guard_pages ||
                                        g_mapguard_policy.panic_on_violation ||
                                        g_mapguard_policy.poison_on_allocation ||
                                        g_mapguard_policy.use_mapping_cache;

    if(g_mapguard_policy.enable_guard_pages == 1 && g_mapguard_policy.use_mapping_cache == 0) {
        LOG_AND_ABORT("MG_ENABLE_GUARD_PAGES == 1 but MG_USE_MAPPING_CACHE == 0");
    }

    g_real_mmap = dlsym(RTLD_NEXT, "mmap");
    g_real_munmap = dlsym(RTLD_NEXT, "munmap");
    g_real_mprotect = dlsym(RTLD_NEXT, "mprotect");
    g_real_mremap = dlsym(RTLD_NEXT, "mremap");

    if(g_mapguard_policy.enable_syslog) {
        openlog("mapguard", LOG_CONS | LOG_PID, LOG_AUTH);
    }

    mg_internal = 1;
    mce_head = new_mce_page();
    mg_internal = 0;
    LOG("Allocated mce_head at %p", mce_head);

    /* Start snapshot thread after everything is initialized */
    mg_snapshot_thread_start();
}

__attribute__((destructor)) void mapguard_dtor() {
    /* Stop snapshot thread first and join */
    mg_snapshot_thread_stop();

    /* Take one final snapshot */
    mg_tracker_take_snapshot();

    /* Check growth one last time */
    if(mg_tracker_check_growth()) {
        fprintf(stderr, "[MapGuard] GROWTH WARNING (final): Memory usage increased by >= %lu bytes\n",
                (unsigned long)mg_growth_threshold_bytes);
    }

    /* Generate final report (does NOT hold lock during file I/O) */
    mg_tracker_generate_report();

    if(g_mapguard_policy.enable_syslog) {
        closelog();
    }

    /* Clean up MCE pages */
    LOCK_MG();
    mapguard_cache_metadata_t *current = mce_head;
    while(current != NULL) {
#if DEBUG
        if(current->free != current->total) {
            LOG("Memory leak detected: MCE page at %p has %d/%d used entries",
                current, current->total - current->free, current->total);
        }
#endif
        mapguard_cache_metadata_t *tmp = current->next;
        uint8_t *base = (uint8_t *)current - g_page_size;
        mg_internal = 1;
        g_real_munmap(base, g_page_size * 3);
        mg_internal = 0;
        current = tmp;
    }
    UNLOCK_MG();
}

/* ===================================================================
 * HOOKED LIBC FUNCTIONS
 * =================================================================== */

/* Hook mmap in libc */
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    /* We don't intercept file backed mappings */
    if(fd != -1) {
        return g_real_mmap(addr, length, prot, flags, fd, offset);
    }

    size_t rounded_length = ROUND_UP_PAGE(length);
    const bool is_rwx = (prot & PROT_WRITE) && (prot & PROT_EXEC);

    /* Fast path: no policies enabled, no tracking needed */
    if(g_mapguard_policy.prevent_policies_enabled == 0 && g_mapguard_policy.actions_enabled == 0) {
        void *ptr = g_real_mmap(addr, rounded_length, prot, flags, fd, offset);
        /* Track even in fast path, unless we're inside MapGuard */
        if(ptr != MAP_FAILED && !mg_internal) {
            mg_tracker_record_alloc(ptr, rounded_length, (uintptr_t)__builtin_return_address(0));
        }
        return ptr;
    }

    /* Policy checks */
    if(g_mapguard_policy.prevent_rwx && is_rwx) {
        LOG("Preventing RWX memory allocation");
        MAYBE_PANIC();
        return MAP_FAILED;
    }

    if(g_mapguard_policy.prevent_static_address && addr != 0) {
        LOG("Preventing memory allocation at static address %p", addr);
        MAYBE_PANIC();
        return MAP_FAILED;
    }

    /* Perform the actual mmap */
    void *map_ptr;
    size_t alloc_length = rounded_length;

    if(g_mapguard_policy.enable_guard_pages) {
        alloc_length += (g_page_size << 1);
    }

    map_ptr = g_real_mmap(addr, alloc_length, prot, flags, fd, offset);

    if(map_ptr == MAP_FAILED) {
        return MAP_FAILED;
    }

    if(g_mapguard_policy.enable_guard_pages) {
        mg_internal = 1;
        make_guard_page(map_ptr);
        make_guard_page(map_ptr + g_page_size + rounded_length);
        mg_internal = 0;
    }

    void *return_ptr = map_ptr;

    if(g_mapguard_policy.use_mapping_cache) {
        LOCK_MG();
        mapguard_cache_entry_t *mce = find_free_mce();

        if(mce == NULL) {
            LOG_AND_ABORT("Failed to find free MCE entry in mmap");
        }

        if(g_mapguard_policy.enable_guard_pages) {
            mce->start = map_ptr + g_page_size;
            mce->guarded_b = true;
            mce->guarded_t = true;
        } else {
            mce->start = map_ptr;
        }

        mce->size = rounded_length;
        mce->immutable_prot = prot;
        mce->current_prot = prot;
        mce->alloc_ts = mg_now_ns();
        mce->call_site = (uintptr_t)__builtin_return_address(0);
        cache_entry_insert(mce);

        if(g_mapguard_policy.poison_on_allocation && (prot & PROT_WRITE)) {
            memset(mce->start, MG_POISON_BYTE, length);
        }

        return_ptr = mce->start;
        UNLOCK_MG();
    }

    if(!g_mapguard_policy.use_mapping_cache &&
       g_mapguard_policy.poison_on_allocation && (prot & PROT_WRITE)) {
        memset(map_ptr, MG_POISON_BYTE, length);
    }

    /* Record in leak tracker (only for application allocations) */
    if(!mg_internal) {
        mg_tracker_record_alloc(return_ptr, rounded_length,
                                (uintptr_t)__builtin_return_address(0));
    }

    return return_ptr;
}

/* Hook munmap in libc */
int munmap(void *addr, size_t length) {
    if(length == 0) {
        return EINVAL;
    }

    if(((uintptr_t)addr & (g_page_size - 1)) != 0) {
        return EINVAL;
    }

    size_t rounded_length = ROUND_UP_PAGE(length);

    /* Fast path when mapping cache disabled */
    if(g_mapguard_policy.use_mapping_cache == false) {
        int ret = g_real_munmap(addr, rounded_length);
        if(ret == 0 && !mg_internal) {
            mg_tracker_record_free(addr, rounded_length);
        }
        return ret;
    }

    LOCK_MG();
    mapguard_cache_entry_t *mce = get_cache_entry(addr);

    if(mce == NULL) {
        UNLOCK_MG();
        /* Not in our cache - could be file-backed or external mapping */
        int ret = g_real_munmap(addr, rounded_length);
        if(ret == 0 && !mg_internal) {
            mg_tracker_record_free(addr, rounded_length);
        }
        return ret;
    }

    int32_t ret = 0;
    size_t length_pages = rounded_length;

    /* Case 1: Full unmap */
    if(mce->start == addr && mce->size == length_pages) {
        void *unmap_addr = addr;
        size_t unmap_len = length_pages;

        if(g_mapguard_policy.enable_guard_pages && mce->guarded_b) {
            unmap_len += g_page_size;
            unmap_addr = (void *)((uintptr_t)addr - g_page_size);
        }
        if(g_mapguard_policy.enable_guard_pages && mce->guarded_t) {
            unmap_len += g_page_size;
        }

        mg_internal = 1;
        ret = g_real_munmap(unmap_addr, unmap_len);
        mg_internal = 0;

        if(ret != 0) {
            UNLOCK_MG();
            return ret;
        }

        /* Save info before clearing */
        void *freed_addr = mce->start;
        size_t freed_size = mce->size;

        cache_entry_remove(mce);
        mapguard_cache_metadata_t *metadata = (mapguard_cache_metadata_t *)ROUND_DOWN_PAGE((uintptr_t)mce);
        metadata->free++;
        memset(mce, 0, sizeof(mapguard_cache_entry_t));

        UNLOCK_MG();

        if(!mg_internal) {
            mg_tracker_record_free(freed_addr, freed_size);
        }
        return ret;
    }

    /* Case 2: Partial unmap from beginning */
    if(mce->start == addr && length_pages < mce->size) {
        void *orig_start = mce->start;
        (void)mce->size;   /* orig_size not needed here */
        (void)mce->alloc_ts;  /* recorded via tracker */
        (void)mce->call_site; /* recorded via tracker */

        if(mce->guarded_b == true) {
            void *unmap_addr = addr - g_page_size;
            mg_internal = 1;
            ret = g_real_munmap(unmap_addr, length_pages);
            mg_internal = 0;
            if(ret != 0) {
                UNLOCK_MG();
                return ret;
            }
            void *new_guard_addr = unmap_addr + length_pages;
            mg_internal = 1;
            g_real_mprotect(new_guard_addr, g_page_size, PROT_READ | PROT_WRITE);
            memset(new_guard_addr, 0, g_page_size);
            make_guard_page(new_guard_addr);
            mg_internal = 0;
            cache_entry_remove(mce);
            mce->start = new_guard_addr + g_page_size;
            mce->size -= length_pages;
        } else {
            mg_internal = 1;
            ret = g_real_munmap(addr, length_pages);
            mg_internal = 0;
            if(ret != 0) {
                UNLOCK_MG();
                return ret;
            }
            cache_entry_remove(mce);
            mce->start = addr + length_pages;
            mce->size -= length_pages;
        }

        cache_entry_insert(mce);
        UNLOCK_MG();

        if(!mg_internal) {
            mg_tracker_record_partial_free(orig_start, length_pages,
                                           mce->start, mce->size);
        }
        return ret;
    }

    /* Case 3: Partial unmap from end */
    if(addr >= mce->start && (addr + length_pages) == (mce->start + mce->size)) {
        void *orig_start = mce->start;
        (void)mce->alloc_ts;  /* recorded via tracker */
        (void)mce->call_site; /* recorded via tracker */

        if(g_mapguard_policy.enable_guard_pages && mce->guarded_t) {
            mg_internal = 1;
            ret = g_real_munmap(addr + g_page_size, length_pages);
            mg_internal = 0;
            if(ret != 0) {
                UNLOCK_MG();
                return ret;
            }
            mg_internal = 1;
            g_real_mprotect(addr, g_page_size, PROT_READ | PROT_WRITE);
            memset(addr, 0, g_page_size);
            make_guard_page(addr);
            mg_internal = 0;
            mce->size = addr - mce->start;
        } else {
            mg_internal = 1;
            ret = g_real_munmap(addr, length_pages);
            mg_internal = 0;
            if(ret != 0) {
                UNLOCK_MG();
                return ret;
            }
            mce->size = addr - mce->start;
        }

        UNLOCK_MG();

        if(!mg_internal) {
            mg_tracker_record_partial_free(orig_start, length_pages,
                                           mce->start, mce->size);
        }
        return ret;
    }

    /* Case 4: Split (unmap middle hole) */
    if(addr >= mce->start && (addr + length_pages) < (mce->start + mce->size)) {
        void *orig_start = mce->start;
        uint64_t orig_ts = mce->alloc_ts;
        uintptr_t orig_site = mce->call_site;

        void *upper_start = addr + length_pages;
        size_t upper_size = (mce->start + mce->size) - upper_start;
        size_t lower_size = addr - mce->start;

        mapguard_cache_entry_t *upper_mce = find_free_mce();
        if(upper_mce == NULL) {
            UNLOCK_MG();
            LOG_AND_ABORT("Failed to allocate MCE for split mapping");
        }

        if(g_mapguard_policy.enable_guard_pages) {
            if(length_pages == g_page_size) {
                mg_internal = 1;
                g_real_mprotect(addr, g_page_size, PROT_READ | PROT_WRITE);
                memset(addr, 0, g_page_size);
                make_guard_page(addr);
                mg_internal = 0;
                mce->guarded_t = true;
                upper_mce->guarded_b = false;
                upper_mce->guarded_t = mce->guarded_t;
            } else if(length_pages == (g_page_size * 2)) {
                mg_internal = 1;
                g_real_mprotect(addr, g_page_size, PROT_READ | PROT_WRITE);
                memset(addr, 0, g_page_size);
                make_guard_page(addr);
                mg_internal = 0;
                mce->guarded_t = true;

                void *upper_guard = addr + g_page_size;
                mg_internal = 1;
                g_real_mprotect(upper_guard, g_page_size, PROT_READ | PROT_WRITE);
                memset(upper_guard, 0, g_page_size);
                make_guard_page(upper_guard);
                mg_internal = 0;
                upper_mce->guarded_b = true;
                upper_start = upper_guard + g_page_size;
                upper_size = (mce->start + mce->size) - upper_start;
                upper_mce->guarded_t = true;
            } else {
                mg_internal = 1;
                g_real_mprotect(addr, g_page_size, PROT_READ | PROT_WRITE);
                memset(addr, 0, g_page_size);
                make_guard_page(addr);
                mg_internal = 0;
                mce->guarded_t = true;

                void *upper_guard = addr + length_pages - g_page_size;
                mg_internal = 1;
                g_real_mprotect(upper_guard, g_page_size, PROT_READ | PROT_WRITE);
                memset(upper_guard, 0, g_page_size);
                make_guard_page(upper_guard);
                mg_internal = 0;
                upper_mce->guarded_b = true;

                void *unmap_start = addr + g_page_size;
                size_t unmap_length = length_pages - (g_page_size * 2);
                mg_internal = 1;
                ret = g_real_munmap(unmap_start, unmap_length);
                mg_internal = 0;

                if(ret != 0) {
                    memset(upper_mce, 0, sizeof(mapguard_cache_entry_t));
                    mapguard_cache_metadata_t *metadata = (mapguard_cache_metadata_t *)ROUND_DOWN_PAGE((uintptr_t)upper_mce);
                    metadata->free++;
                    UNLOCK_MG();
                    return ret;
                }

                upper_start = upper_guard + g_page_size;
                upper_size = (mce->start + mce->size) - upper_start;
                upper_mce->guarded_t = mce->guarded_t;
            }
        } else {
            mg_internal = 1;
            ret = g_real_munmap(addr, length_pages);
            mg_internal = 0;
            if(ret != 0) {
                memset(upper_mce, 0, sizeof(mapguard_cache_entry_t));
                mapguard_cache_metadata_t *metadata = (mapguard_cache_metadata_t *)ROUND_DOWN_PAGE((uintptr_t)upper_mce);
                metadata->free++;
                UNLOCK_MG();
                return ret;
            }
        }

        upper_mce->start = upper_start;
        upper_mce->size = upper_size;
        upper_mce->immutable_prot = mce->immutable_prot;
        upper_mce->current_prot = mce->current_prot;
        upper_mce->alloc_ts = mce->alloc_ts;
        upper_mce->call_site = mce->call_site;
        cache_entry_insert(upper_mce);

        mce->size = lower_size;

        UNLOCK_MG();

        if(!mg_internal) {
            mg_tracker_record_split(orig_start,
                                    mce->start, lower_size,
                                    upper_start, upper_size,
                                    orig_ts, orig_site);
        }
        return 0;
    }

    UNLOCK_MG();

    /* Unknown partial unmap case - just forward */
    mg_internal = 1;
    ret = g_real_munmap(addr, length_pages);
    mg_internal = 0;
    return ret;
}

/* Hook mprotect in libc */
int mprotect(void *addr, size_t len, int prot) {
    mapguard_cache_entry_t *mce = NULL;
    int32_t ret;

    if(g_mapguard_policy.prevent_rwx && (prot & PROT_WRITE) && (prot & PROT_EXEC)) {
        LOG("Preventing RWX mprotect");
        MAYBE_PANIC();
        return ERROR;
    }

    if(g_mapguard_policy.use_mapping_cache) {
        LOCK_MG();
        mce = get_cache_entry(addr);

        if(mce != NULL) {
            if(g_mapguard_policy.prevent_transition_to_x && (prot & PROT_EXEC) && (mce->immutable_prot & PROT_WRITE)) {
                LOG("Cannot allow mapping %p to be set PROT_EXEC, it was previously PROT_WRITE", addr);
                MAYBE_PANIC();
                errno = EINVAL;
                UNLOCK_MG();
                return ERROR;
            }

            if(g_mapguard_policy.prevent_transition_from_x && (prot & PROT_WRITE) && (mce->immutable_prot & PROT_EXEC)) {
                LOG("Cannot allow mapping %p to transition from PROT_EXEC to PROT_WRITE", addr);
                MAYBE_PANIC();
                errno = EINVAL;
                UNLOCK_MG();
                return ERROR;
            }
        }

        ret = g_real_mprotect(addr, len, prot);

        if(ret == 0 && mce) {
            if(mce->size != len) {
                LOG("Cached mapping size %zu bytes but mprotected %zu bytes", mce->size, len);
            }
            mce->immutable_prot |= prot;
            mce->current_prot = prot;
        }

        UNLOCK_MG();
    } else {
        ret = g_real_mprotect(addr, len, prot);
    }

    return ret;
}

/* Hook mremap in libc */
void *mremap(void *__addr, size_t __old_len, size_t __new_len, int __flags, ...) {
    void *new_address = NULL;
    void *map_ptr = NULL;

    if((__flags & MREMAP_FIXED) || (__flags & MAP_FIXED_NOREPLACE)) {
        va_list vl;
        va_start(vl, __flags);
        new_address = va_arg(vl, void *);
        va_end(vl);
        if(g_mapguard_policy.prevent_static_address) {
            LOG("Attempted mremap with MREMAP_FIXED at %p", new_address);
            MAYBE_PANIC();
            errno = EINVAL;
            return MAP_FAILED;
        }
    }

    size_t rounded_old_len = ROUND_UP_PAGE(__old_len);
    size_t rounded_new_len = ROUND_UP_PAGE(__new_len);

    if(new_address != NULL) {
        map_ptr = g_real_mremap(__addr, rounded_old_len, rounded_new_len, __flags, new_address);
    } else {
        map_ptr = g_real_mremap(__addr, rounded_old_len, rounded_new_len, __flags);
    }

    if(map_ptr == MAP_FAILED) {
        return MAP_FAILED;
    }

    if(g_mapguard_policy.use_mapping_cache) {
        LOCK_MG();
        mapguard_cache_entry_t *mce = get_cache_entry(__addr);

        if(mce) {
            if(mce->start != map_ptr) {
                unmap_guard_pages(mce);
                mce->guarded_b = false;
                mce->guarded_t = false;
                cache_entry_remove(mce);
                mce->start = map_ptr;
                mce->size = rounded_new_len;
                cache_entry_insert(mce);
            } else {
                mce->size = rounded_new_len;
            }

            /* Best effort guard page creation */
            void *expected_bottom = map_ptr - g_page_size;
            mg_internal = 1;
            void *ptr = g_real_mmap(expected_bottom, g_page_size, PROT_NONE,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            mg_internal = 0;
            if(ptr != MAP_FAILED) {
                if(ptr == expected_bottom) {
                    mce->guarded_b = true;
                } else {
                    mg_internal = 1;
                    g_real_munmap(ptr, g_page_size);
                    mg_internal = 0;
                }
            }

            void *expected_top = map_ptr + rounded_new_len;
            mg_internal = 1;
            ptr = g_real_mmap(expected_top, g_page_size, PROT_NONE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            mg_internal = 0;
            if(ptr != MAP_FAILED) {
                if(ptr == expected_top) {
                    mce->guarded_t = true;
                } else {
                    mg_internal = 1;
                    g_real_munmap(ptr, g_page_size);
                    mg_internal = 0;
                }
            }
        }

        UNLOCK_MG();
    }

    /* Update leak tracker - preserves original timestamp and call site */
    if(!mg_internal) {
        mg_tracker_record_remap(__addr, map_ptr, rounded_old_len, rounded_new_len);
    }

    return map_ptr;
}
