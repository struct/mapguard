/* MapGuard - Copyright Chris Rohlf - 2025 */

#include "mapguard.h"

pthread_mutex_t _mg_mutex;

mapguard_cache_metadata_t *mce_head;

#define HASH_TABLE_SIZE 16384  /* Power of 2 for fast modulo */
#define HASH_ADDR(addr) (((uintptr_t)(addr) >> 12) & (HASH_TABLE_SIZE - 1))

mapguard_cache_entry_t *g_hash_table[HASH_TABLE_SIZE];

/* Globals */
size_t g_page_size;

/* Global policy configuration object */
mapguard_policy_t g_mapguard_policy;

/* Pointers to hooked libc functions */
void *(*g_real_mmap)(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int (*g_real_munmap)(void *addr, size_t length);
int (*g_real_mprotect)(void *addr, size_t len, int prot);
void *(*g_real_mremap)(void *__addr, size_t __old_len, size_t __new_len, int __flags, ...);

__attribute__((constructor)) void mapguard_ctor() {
#if THREAD_SUPPORT
    pthread_mutex_init(&_mg_mutex, NULL);
#endif

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

    /* In order for guard pages to work we need MCE */
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

    g_page_size = getpagesize();
    mce_head = new_mce_page();
    LOG("Allocated mce_head at %p", mce_head);
}

mapguard_cache_metadata_t *new_mce_page() {
    /* Produce a random page address as a hint for mmap */
    uint64_t hint = ROUND_DOWN_PAGE(rand_uint64());
    hint &= 0x3FFFFFFFF000;

    void *ptr = g_real_mmap((void *) hint, g_page_size * 3, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if(ptr == MAP_FAILED) {
        LOG_AND_ABORT("mmap failed in new_mce_page");
        abort();
    }

    make_guard_page((void *) ptr);
    make_guard_page((void *) ptr + (g_page_size * 2));

    mapguard_cache_metadata_t *t = (mapguard_cache_metadata_t *) (ptr + g_page_size);
    t->total = (g_page_size - sizeof(mapguard_cache_metadata_t)) / sizeof(mapguard_cache_entry_t);
    t->free = t->total;
    t->next = NULL;
    return t;
}

/* Attempts to allocate a guard page at a given address */
void *allocate_guard_page(void *p) {
    return g_real_mmap(p, g_page_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

void make_guard_page(void *p) {
    g_real_mprotect(p, g_page_size, PROT_NONE);
    madvise(p, g_page_size, MADV_DONTNEED);
    LOG("Mapped guard page %p", p);
}

void unmap_top_guard_page(mapguard_cache_entry_t *mce) {
#if DEBUG
    if(mce->guarded_t == false) {
        LOG_AND_ABORT("Attempting to unmap missing top guard page")
    }
#endif
    g_real_munmap(mce->start + mce->size, g_page_size);
    mce->guarded_t = false;
    LOG("Unmapped top guard page %p", mce->start + mce->size);
}

void unmap_bottom_guard_page(mapguard_cache_entry_t *mce) {
#if DEBUG
    if(mce->guarded_b == false) {
        LOG_AND_ABORT("Attempting to unmap missing bottom guard page")
    }
#endif
    g_real_munmap(mce->start - g_page_size, g_page_size);
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
            mapguard_cache_entry_t *entries = (mapguard_cache_entry_t *) ((uint8_t *)current + sizeof(mapguard_cache_metadata_t));

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
    return (mapguard_cache_entry_t *) ((uint8_t *)new_page + sizeof(mapguard_cache_metadata_t));
}

__attribute__((destructor)) void mapguard_dtor() {
    LOCK_MG();

    if(g_mapguard_policy.enable_syslog) {
        closelog();
    }

    mapguard_cache_metadata_t *current = mce_head;

    while(current != NULL) {
#if DEBUG
        if(current->free != current->total) {
            LOG("Memory leak detected: MCE page at %p has %d/%d used entries",
                current, current->total - current->free, current->total);
        }
#endif
        mapguard_cache_metadata_t *tmp = current->next;
        uint8_t *base = (uint8_t *) current - g_page_size;
        g_real_munmap(base, g_page_size * 3);
        current = tmp;
    }

    UNLOCK_MG();
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
    /* Round down to page boundary for initial lookup */
    void *page_addr = (void *)ROUND_DOWN_PAGE((uintptr_t)addr);
    uint32_t bucket = HASH_ADDR(page_addr);
    mapguard_cache_entry_t *mce = g_hash_table[bucket];

    while(mce != NULL) {
        /* Check if addr falls within this mapping's range */
        if(addr >= mce->start && addr < (mce->start + mce->size)) {
            return mce;
        }

        mce = mce->hash_next;
    }

    /* Still not found, now backward search for up to 256 pages */
    for(uint32_t i = 1; i < 256; i++) {
        void *probe_addr = page_addr - (i * g_page_size);
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

    /* Insert at head of chain */
    mce->hash_next = g_hash_table[bucket];
    g_hash_table[bucket] = mce;
}

void cache_entry_remove(mapguard_cache_entry_t *mce) {
    uint32_t bucket = HASH_ADDR(mce->start);
    mapguard_cache_entry_t *current = g_hash_table[bucket];
    mapguard_cache_entry_t *prev = NULL;

    while(current != NULL) {
        if(current == mce) {
            /* Found it - remove from chain */
            if(prev == NULL) {
                /* Removing head of chain */
                g_hash_table[bucket] = current->hash_next;
            } else {
                /* Removing from middle/end of chain */
                prev->hash_next = current->hash_next;
            }
            mce->hash_next = NULL;
            /* FIX: Remove free counter management - let caller handle it */
            return;
        }
        prev = current;
        current = current->hash_next;
    }

    LOG_AND_ABORT("Failed to find cache entry to remove");
}

/* Hook mmap in libc */
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    /* We don't intercept file backed mappings */
    if(fd != -1) {
        void *map_ptr = g_real_mmap(addr, length, prot, flags, fd, offset);
        return map_ptr;
    }

    LOCK_MG();

    /* Prevent RWX mappings */
    if(g_mapguard_policy.prevent_rwx && (prot & PROT_WRITE) && (prot & PROT_EXEC)) {
        LOG("Preventing RWX memory allocation");
        MAYBE_PANIC();
        UNLOCK_MG();
        return MAP_FAILED;
    }

    /* Prevent mappings at a hardcoded address. This weakens ASLR */
    if(addr != 0 && g_mapguard_policy.prevent_static_address) {
        LOG("Preventing memory allocation at static address %p", addr);
        MAYBE_PANIC();
        UNLOCK_MG();
        return MAP_FAILED;
    }

    void *map_ptr = NULL;

    size_t rounded_length = ROUND_UP_PAGE(length);

    if(g_mapguard_policy.enable_guard_pages) {
        map_ptr = g_real_mmap(addr, rounded_length + (g_page_size * GUARD_PAGE_COUNT), prot, flags, fd, offset);

        if(map_ptr == MAP_FAILED) {
            UNLOCK_MG();
            return map_ptr;
        }

        make_guard_page(map_ptr);
        make_guard_page(map_ptr + g_page_size + length);
    } else {
        map_ptr = g_real_mmap(addr, rounded_length, prot, flags, fd, offset);

        if(map_ptr == MAP_FAILED) {
            UNLOCK_MG();
            return map_ptr;
        }
    }

    /* Cache the start, size and protections of this mapping */
    if(g_mapguard_policy.use_mapping_cache) {
        mapguard_cache_entry_t *mce = find_free_mce();

        /* This should never happen */
        if(mce == NULL) {
            LOG_AND_ABORT("Failed to find free MCE entry in mmap");
        }

        /* Only offset by guard page if guard pages are enabled */
        if(g_mapguard_policy.enable_guard_pages) {
            mce->start = map_ptr + g_page_size;
            mce->guarded_b = true;
            mce->guarded_t = true;
        } else {
            mce->start = map_ptr;
        }

        mce->size = rounded_length;
        mce->immutable_prot |= prot;
        mce->current_prot = prot;
        cache_entry_insert(mce);

        /* Set all bytes in the allocation if configured and pages are writeable */
        if(g_mapguard_policy.poison_on_allocation && (prot & PROT_WRITE)) {
            memset(mce->start, MG_POISON_BYTE, length);
        }

        UNLOCK_MG();
        return mce->start;
    } else {
        /* Set all bytes in the allocation if configured and pages are writeable */
        if(g_mapguard_policy.poison_on_allocation && (prot & PROT_WRITE)) {
            memset(map_ptr, MG_POISON_BYTE, length);
        }

        UNLOCK_MG();
        return map_ptr;
    }
}

/* Hook munmap in libc */
int munmap(void *addr, size_t length) {
    LOCK_MG();

    mapguard_cache_entry_t *mce = NULL;
    int32_t ret;

    if(length == 0) {
        UNLOCK_MG();
        return EINVAL;
    }

    if(((uintptr_t) addr & (g_page_size - 1)) != 0) {
        UNLOCK_MG();
        return EINVAL;
    }

    length = ROUND_UP_PAGE(length);

    /* Remove tracked pages from the cache and unmap them
     * The cache hash table only has to be updated when
     * mce->start changes because that is how the table
     * is indexed */
    if(g_mapguard_policy.use_mapping_cache) {
        mce = get_cache_entry(addr);

        if(mce == NULL) {
            LOG_AND_ABORT("No mapguard cache entry found for address %p", addr);
        }
        /* Case 1: Handle full unmapping (the most common case) */
        if(mce->start == addr && mce->size == length) {
            if(g_mapguard_policy.enable_guard_pages == true && mce->guarded_b == true) {
                length += g_page_size;
                addr -= g_page_size;
            }

            if(g_mapguard_policy.enable_guard_pages == true && mce->guarded_t == true) {
                length += g_page_size;
            }

            ret = g_real_munmap(addr, length);

            if(ret != 0) {
                UNLOCK_MG();
                return ret;
            }

            cache_entry_remove(mce);

            mapguard_cache_metadata_t *metadata = (mapguard_cache_metadata_t *) ROUND_DOWN_PAGE((uintptr_t)mce);
            metadata->free++;

            memset(mce, 0, sizeof(mapguard_cache_entry_t));
            UNLOCK_MG();
            return ret;
        }

        /* Case 2: Partial unmapping from the beginning of the range */
        if(mce->start == addr && length < mce->size) {
            /* 1. Reuse an existing page as the new bottom guard page */
            if(mce->guarded_b == true) {
                void *unmap_addr = addr - g_page_size;

                ret = g_real_munmap(unmap_addr, length);

                if(ret != 0) {
                    UNLOCK_MG();
                    return ret;
                }

                /* The new guard page is at the first page of remaining allocation */
                void *new_guard_addr = unmap_addr + length;

                /* Temporarily make it writable to zeroize */
                g_real_mprotect(new_guard_addr, g_page_size, PROT_READ | PROT_WRITE);
                memset(new_guard_addr, 0, g_page_size);
                make_guard_page(new_guard_addr);

                cache_entry_remove(mce);
                mce->start = new_guard_addr + g_page_size;
                mce->size -= length;
            } else {
                /* No guard page */
                ret = g_real_munmap(addr, length);

                if(ret != 0) {
                    UNLOCK_MG();
                    return ret;
                }

                cache_entry_remove(mce);
                mce->start = addr + length;
                mce->size -= length;
            }

            cache_entry_insert(mce);
            UNLOCK_MG();
            return ret;
        }

        /* Case 3: Unmapping from middle to the end of the range */
        if(addr >= mce->start && (addr + length) == (mce->start + mce->size)) {
            /* Reuse an existing page as the new top guard page */
            if(g_mapguard_policy.enable_guard_pages == true && mce->guarded_t == true) {
                ret = g_real_munmap(addr + g_page_size, length);

                if(ret != 0) {
                    UNLOCK_MG();
                    return ret;
                }

                /* Temporarily make it writable to zeroize */
                g_real_mprotect(addr, g_page_size, PROT_READ | PROT_WRITE);
                memset(addr, 0, g_page_size);
                make_guard_page(addr);

                mce->size = addr - mce->start;
            } else {
                /* No guard page, simple case */
                ret = g_real_munmap(addr, length);

                if(ret != 0) {
                    UNLOCK_MG();
                    return ret;
                }

                /* Calculate new size */
                mce->size = addr - mce->start;
            }

            UNLOCK_MG();
            return ret;
        }

        /* Case 4: Unmap a hole in the range, split into two regions */
        if(addr >= mce->start && (addr + length) < (mce->start + mce->size)) {
            /* Calculate upper region bounds */
            void *upper_start = addr + length;
            size_t upper_size = (mce->start + mce->size) - upper_start;
            size_t lower_size = addr - mce->start;

            /* Allocate new cache entry for upper region */
            mapguard_cache_entry_t *upper_mce = find_free_mce();

            if(upper_mce == NULL) {
                LOG_AND_ABORT("Failed to allocate MCE for split mapping");
            }

            /* Handle guard pages if enabled */
            if(g_mapguard_policy.enable_guard_pages == true) {
                /* If only unmapping a single page, reuse it as top guard for lower region */
                if(length == g_page_size) {
                    /* Zeroize and convert the unmapped page to a guard page */
                    g_real_mprotect(addr, g_page_size, PROT_READ | PROT_WRITE);
                    memset(addr, 0, g_page_size);
                    make_guard_page(addr);

                    /* Lower region gets new top guard */
                    mce->guarded_t = true;

                    /* Upper region has no bottom guard */
                    upper_mce->guarded_b = false;
                    upper_mce->guarded_t = mce->guarded_t;
                } else if(length == (g_page_size * 2)) {
                    /* If unmapping exactly 2 pages, reuse both as guards */
                    /* First page becomes top guard for lower region */
                    g_real_mprotect(addr, g_page_size, PROT_READ | PROT_WRITE);
                    memset(addr, 0, g_page_size);
                    make_guard_page(addr);
                    mce->guarded_t = true;

                    /* Second page becomes bottom guard for upper region */
                    void *upper_guard = addr + g_page_size;
                    g_real_mprotect(upper_guard, g_page_size, PROT_READ | PROT_WRITE);
                    memset(upper_guard, 0, g_page_size);
                    make_guard_page(upper_guard);
                    upper_mce->guarded_b = true;

                    /* Adjust upper region to account for its new bottom guard */
                    upper_start = upper_guard + g_page_size;
                    upper_size = (mce->start + mce->size) - upper_start;
                    upper_mce->guarded_t = true;
                } else {
                    /* If unmapping 3+ pages, reuse first and last as guards, unmap middle pages */
                    /* First page becomes top guard for lower region */
                    g_real_mprotect(addr, g_page_size, PROT_READ | PROT_WRITE);
                    memset(addr, 0, g_page_size);
                    make_guard_page(addr);
                    mce->guarded_t = true;

                    /* Last page becomes bottom guard for upper region */
                    void *upper_guard = addr + length - g_page_size;
                    g_real_mprotect(upper_guard, g_page_size, PROT_READ | PROT_WRITE);
                    memset(upper_guard, 0, g_page_size);
                    make_guard_page(upper_guard);
                    upper_mce->guarded_b = true;

                    /* Unmap the pages between the two new guard pages */
                    void *unmap_start = addr + g_page_size;
                    size_t unmap_length = length - (g_page_size * 2);
                    ret = g_real_munmap(unmap_start, unmap_length);

                    if(ret != 0) {
                        memset(upper_mce, 0, sizeof(mapguard_cache_entry_t));
                        mapguard_cache_metadata_t *metadata = (mapguard_cache_metadata_t *) ROUND_DOWN_PAGE((uintptr_t)upper_mce);
                        metadata->free++;
                        UNLOCK_MG();
                        return ret;
                    }

                    /* Adjust upper region to account for its new bottom guard */
                    upper_start = upper_guard + g_page_size;
                    upper_size = (mce->start + mce->size) - upper_start;
                    upper_mce->guarded_t = mce->guarded_t;
                }
            } else {
                /* No guard pages enabled, simple unmap */
                ret = g_real_munmap(addr, length);

                if(ret != 0) {
                    memset(upper_mce, 0, sizeof(mapguard_cache_entry_t));
                    mapguard_cache_metadata_t *metadata = (mapguard_cache_metadata_t *) ROUND_DOWN_PAGE((uintptr_t)upper_mce);
                    metadata->free++;
                    UNLOCK_MG();
                    return ret;
                }

                /* No guard pages to track */
                upper_mce->guarded_b = false;
                upper_mce->guarded_t = false;
            }

            /* Initialize upper region MCE (common for both guard/no-guard cases) */
            upper_mce->start = upper_start;
            upper_mce->size = upper_size;
            upper_mce->immutable_prot = mce->immutable_prot;
            upper_mce->current_prot = mce->current_prot;
            cache_entry_insert(upper_mce);

            /* Update lower region (original MCE) */
            mce->size = lower_size;

            UNLOCK_MG();
            return 0;
        }

        /* Unknown partial unmap case */
        LOG_AND_ABORT("Unknown partial munmap case: addr=%p, length=%zu, mce->start=%p, mce->size=%zu",
            addr, length, mce->start, mce->size);
    }

    UNLOCK_MG();
    return g_real_munmap(addr, length);
}

/* Hook mprotect in libc */
int mprotect(void *addr, size_t len, int prot) {
    LOCK_MG();
    mapguard_cache_entry_t *mce = NULL;

    /* Prevent RWX mappings */
    if(g_mapguard_policy.prevent_rwx && (prot & PROT_WRITE) && (prot & PROT_EXEC)) {
        LOG("Preventing RWX mprotect");
        MAYBE_PANIC();
        UNLOCK_MG();
        return ERROR;
    }

    /* Prevent transition to/from X (requires the mapping cache) */
    if(g_mapguard_policy.use_mapping_cache) {
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
    }

    int32_t ret = g_real_mprotect(addr, len, prot);

    if(ret == 0 && mce) {
        /* Its possible the caller changed the protections on
         * only a portion of the mapping. Log it but ignore it */
        if(mce->size != len) {
            LOG("Cached mapping size %zu bytes but mprotected %zu bytes", mce->size, len);
        }

        /* Update the saved page permissions, even if the size doesn't match */
        mce->immutable_prot |= prot;
        mce->current_prot = prot;
    }

    UNLOCK_MG();
    return ret;
}

/* Hook mremap in libc
 * mremap is a complex syscall when you consider all of the flags.
 * Instead of trying to intelligently handle these flags we just
 * transparently proxy the call and do our best to handle what the
 * kernel decides to do with the mapping.
 */
void *mremap(void *__addr, size_t __old_len, size_t __new_len, int __flags, ...) {
    LOCK_MG();

    void *new_address = NULL;

    if((__flags & MREMAP_FIXED) || (__flags & MAP_FIXED_NOREPLACE)) {
        va_list vl;
        va_start(vl, __flags);
        new_address = va_arg(vl, void *);

        if(g_mapguard_policy.prevent_static_address) {
            LOG("Attempted mremap with MREMAP_FIXED at %p", new_address);
            MAYBE_PANIC();
            errno = EINVAL;
            UNLOCK_MG();
            return MAP_FAILED;  /* FIX: Return MAP_FAILED instead of NULL */
        }
    }

    void *map_ptr = NULL;

    if(new_address != NULL) {
        map_ptr = g_real_mremap(__addr, __old_len, __new_len, __flags, new_address);
    } else {
        map_ptr = g_real_mremap(__addr, __old_len, __new_len, __flags);
    }

    if(g_mapguard_policy.use_mapping_cache && map_ptr != MAP_FAILED) {
        mapguard_cache_entry_t *mce = get_cache_entry(__addr);

        /* We are remapping a previously tracked allocation. This
         * means we may have to reallocate guard pages and update
         * the status of our cache */
        if(mce && map_ptr != MAP_FAILED) {
            /* mremap may just allocate new pages above the
             * existing allocation to resize it. If it does
             * then theres no need to unmap/remap the bottom
             * guard page. If guard pages are configured then
             * its probably not possible for mremap to grow
             * the allocation in place anyway but this is a
             * cheap check regardless */
            if(mce->start != map_ptr) {
                unmap_guard_pages(mce);
                mce->guarded_b = false;
                mce->guarded_t = false;

                /* FIX: Remove from old hash bucket before updating start address */
                cache_entry_remove(mce);
                mce->start = map_ptr;
                mce->size = __new_len;
                cache_entry_insert(mce);
            } else {
                mce->size = __new_len;
            }

            /* Best effort guard page creation */
            void *expected_bottom = map_ptr - g_page_size;
            void *ptr = g_real_mmap(expected_bottom, g_page_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

            if(ptr != MAP_FAILED) {
                /* FIX: Verify we actually got the address we wanted */
                if (ptr == expected_bottom) {
                    mce->guarded_b = true;
                } else {
                    g_real_munmap(ptr, g_page_size);
                }
            }

            void *expected_top = map_ptr + __new_len;
            ptr = g_real_mmap(expected_top, g_page_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

            if(ptr != MAP_FAILED) {
                /* FIX: Verify we actually got the address we wanted */
                if (ptr == expected_top) {
                    mce->guarded_t = true;
                } else {
                    g_real_munmap(ptr, g_page_size);
                }
            }
        }
    }

    UNLOCK_MG();  /* FIX: Add missing unlock before return */
    return map_ptr;
}
