/* Reference implementation of map guard
 * Copyright Chris Rohlf - 2022 */

#include "mapguard.h"

pthread_mutex_t _mg_mutex;

mapguard_cache_metadata_t *mce_head;

__attribute__((constructor)) void mapguard_ctor() {
    pthread_mutex_init(&_mg_mutex, NULL);

    /* Enable configuration of mapguard via environment
     * variables during DSO load time only */
    ENV_TO_INT(MG_DISALLOW_RWX, g_mapguard_policy.disallow_rwx);
    ENV_TO_INT(MG_DISALLOW_TRANSITION_TO_X, g_mapguard_policy.disallow_transition_to_x);
    ENV_TO_INT(MG_DISALLOW_TRANSITION_FROM_X, g_mapguard_policy.disallow_transition_from_x);
    ENV_TO_INT(MG_DISALLOW_STATIC_ADDRESS, g_mapguard_policy.disallow_static_address);
    ENV_TO_INT(MG_ENABLE_GUARD_PAGES, g_mapguard_policy.enable_guard_pages);
    ENV_TO_INT(MG_PANIC_ON_VIOLATION, g_mapguard_policy.panic_on_violation);
    ENV_TO_INT(MG_POISON_ON_ALLOCATION, g_mapguard_policy.poison_on_allocation);
    ENV_TO_INT(MG_USE_MAPPING_CACHE, g_mapguard_policy.use_mapping_cache);
    ENV_TO_INT(MG_ENABLE_SYSLOG, g_mapguard_policy.enable_syslog);

    /* In order for guard pages to work we need MCE */
    if(g_mapguard_policy.enable_guard_pages == 1 && g_mapguard_policy.use_mapping_cache == 0) {
        abort();
    }

    g_real_mmap = dlsym(RTLD_NEXT, "mmap");
    g_real_munmap = dlsym(RTLD_NEXT, "munmap");
    g_real_mprotect = dlsym(RTLD_NEXT, "mprotect");
    g_real_mremap = dlsym(RTLD_NEXT, "mremap");

#if MPK_SUPPORT
    g_real_pkey_mprotect = dlsym(RTLD_NEXT, "pkey_mprotect");
    g_real_pkey_alloc = dlsym(RTLD_NEXT, "pkey_alloc");
    g_real_pkey_free = dlsym(RTLD_NEXT, "pkey_free");
    g_real_pkey_set = dlsym(RTLD_NEXT, "pkey_set");
    g_real_pkey_get = dlsym(RTLD_NEXT, "pkey_get");
#endif

    if(g_mapguard_policy.enable_syslog) {
        openlog("mapguard", LOG_CONS | LOG_PID, LOG_AUTH);
    }

    vector_init(&g_map_cache_vector);

    g_page_size = getpagesize();
    mce_head = new_mce_page();
}

mapguard_cache_metadata_t *new_mce_page() {
    /* Produce a random page address as a hint for mmap */
    uint64_t hint = ROUND_DOWN_PAGE(rand_uint64());
    hint &= 0x3FFFFFFFF000;
    void *p = (void *) hint;

    void *ptr = g_real_mmap(p, g_page_size * 3, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    protect_guard_page((void *) ptr);
    protect_guard_page((void *) ptr + (g_page_size * 2));
    mapguard_cache_metadata_t *t = (mapguard_cache_metadata_t *) (ptr + g_page_size);
    t->total = (g_page_size - sizeof(mapguard_cache_metadata_t)) / sizeof(mapguard_cache_entry_t);
    t->free = t->total;
    return t;
}

/* Attempts to allocate a guard page at a given address */
void *allocate_guard_page(void *p) {
    return g_real_mmap(p, g_page_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

void protect_guard_page(void *p) {
    mprotect(p, g_page_size, PROT_NONE);
    madvise(p, g_page_size, MADV_DONTNEED);
}

void unmap_top_guard_page(mapguard_cache_entry_t *mce) {
    g_real_munmap(mce->start + mce->size, g_page_size);
    mce->guarded_t = true;
    LOG("Unmapped top guard page %p", mce->start + mce->size);
}

void unmap_bottom_guard_page(mapguard_cache_entry_t *mce) {
    g_real_munmap(mce->start - g_page_size, g_page_size);
    mce->guarded_b = true;
    LOG("Unmapped bottom guard page %p", mce->start - g_page_size);
}

void unmap_guard_pages(mapguard_cache_entry_t *mce) {
    unmap_bottom_guard_page(mce);
    unmap_top_guard_page(mce);
}

void map_bottom_guard_page(mapguard_cache_entry_t *mce) {
    protect_guard_page(mce->start - g_page_size);
    mce->guarded_b = true;
}

void map_top_guard_page(mapguard_cache_entry_t *mce) {
    protect_guard_page(mce->start + mce->size);
    mce->guarded_t = true;
}

void mark_guard_pages(mapguard_cache_entry_t *mce) {
    map_bottom_guard_page(mce);
    map_top_guard_page(mce);
}

mapguard_cache_entry_t *find_free_mce() {
    mapguard_cache_entry_t *mce = NULL;
    mapguard_cache_metadata_t *current = mce_head;

    while(current != NULL) {
        /* If count is 0 then all entries on this
         * page have been used, goto the next */
        if(current->free == 0) {
            current = current->next;
            continue;
        } else {
            mce = (mapguard_cache_entry_t *) (current + sizeof(mapguard_cache_metadata_t));
            uint32_t i = 0;
            while(mce->start != NULL && i < current->total) {
                mce++;
            }

            /* This page was supposed to have a free entry */
            if(mce->start != NULL || i > current->total) {
                abort();
            }

            /* We have a usable mce entry */
            return mce;
        }
    }

    /* We need a new page */
    while(current != NULL) {
        if(current->next == NULL){
            current->next = new_mce_page();
            mce = (mapguard_cache_entry_t *) (current->next + sizeof(mapguard_cache_metadata_t));
            return mce;
        }
    }

    abort();
    return NULL;
}

__attribute__((destructor)) void mapguard_dtor() {
    if(g_mapguard_policy.enable_syslog) {
        closelog();
    }

    /* Erase all cache entries */
    if(g_mapguard_policy.use_mapping_cache) {
        vector_free(&g_map_cache_vector);
    }

    mapguard_cache_metadata_t *current = mce_head;

    while(current != NULL) {
        mapguard_cache_metadata_t *tmp = current->next;
        g_real_munmap(current, g_page_size);
        current = tmp;
    }
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

    return strtoul(p, NULL, 0);
}

/* Checks if we have a cache entry for this mapping */
void *is_mapguard_entry_cached(void *p, void *data) {
    mapguard_cache_entry_t *mce = (mapguard_cache_entry_t *) p;

    if(mce->start == data) {
        return mce;
    }

    /* This address is within the range of a cached mapping */
    if(data > mce->start && mce->start + mce->size > data) {
        return mce;
    }

    return NULL;
}

mapguard_cache_entry_t *get_cache_entry(void *addr) {
    mapguard_cache_entry_t *mce = (mapguard_cache_entry_t *) vector_for_each(&g_map_cache_vector, (vector_for_each_callback_t *) is_mapguard_entry_cached, addr);
    return mce;
}

/* Hook mmap in libc */
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    /* We don't intercept file backed mappings */
    if(fd != -1) {
        void *map_ptr = g_real_mmap(addr, length, prot, flags, fd, offset);
        return map_ptr;
    }

    /* Evaluate and enforce security policies set by env vars */
    LOCK_MG();

    /* Disallow RWX mappings */
    if(g_mapguard_policy.disallow_rwx && (prot & PROT_WRITE) && (prot & PROT_EXEC)) {
        SYSLOG("Disallowing RWX memory allocation");
        MAYBE_PANIC();
        UNLOCK_MG();
        return MAP_FAILED;
    }

    /* Disallow mappings at a hardcoded address. This weakens ASLR */
    if(addr != 0 && g_mapguard_policy.disallow_static_address) {
        SYSLOG("Disallowing memory allocation at static address %p", addr);
        MAYBE_PANIC();
        UNLOCK_MG();
        return MAP_FAILED;
    }

    void *map_ptr = NULL;

    size_t total_bytes = length;

    if(g_mapguard_policy.enable_guard_pages) {
        total_bytes = length + (g_page_size * GUARD_PAGE_COUNT);
        map_ptr = g_real_mmap(addr, total_bytes, prot, flags, fd, offset);
        protect_guard_page(map_ptr);
        protect_guard_page(map_ptr + g_page_size + length);
    } else {
        map_ptr = g_real_mmap(addr, length, prot, flags, fd, offset);
    }

    if(map_ptr == MAP_FAILED) {
        UNLOCK_MG();
        return map_ptr;
    }

    mapguard_cache_entry_t *mce = NULL;

    /* Cache the start, size and protections of this mapping */
    if(g_mapguard_policy.use_mapping_cache) {
        mce = find_free_mce();

        /* This should never happen */
        if(mce == NULL) {
            abort();
        }

        mce->start = map_ptr + g_page_size;
        mce->size = total_bytes;
        mce->immutable_prot |= prot;
        mce->current_prot = prot;
        mce->cache_index = vector_push(&g_map_cache_vector, mce);

        if(g_mapguard_policy.enable_guard_pages) {
            mce->guarded_b = true;
            mce->guarded_t = true;
        }
    }

    /* Set all bytes in the allocation if configured and pages are writeable */
    if(g_mapguard_policy.poison_on_allocation && (prot & PROT_WRITE)) {
        memset(mce->start, MG_POISON_BYTE, length);
    }

    UNLOCK_MG();
    return mce->start;
}

/* Hook munmap in libc */
int munmap(void *addr, size_t length) {
    LOCK_MG();

    mapguard_cache_entry_t *mce = NULL;
    int32_t ret = 0;

    /* Remove tracked pages from the cache */
    if(g_mapguard_policy.use_mapping_cache) {
        mce = get_cache_entry(addr);

        if(mce) {
            LOG("Found mapguard cache entry for mapping %p", mce->start);

            /* Handle a partial unmapping */
            if(mce->start != addr || mce->size != length) {
                /* Update the size we are tracking */
                mce->size -= length;

                /* Handle the case of unmapping the last N pages */
                if(addr > mce->start && length < mce->size) {
                    unmap_top_guard_page(mce);
                    ret = g_real_munmap(addr, length);

                    /* If the unmapping succeeded remap the top guard page */
                    if(ret == 0) {
                        void *p = allocate_guard_page(mce->start + mce->size);

                        if(p == MAP_FAILED) {
                            mce->guarded_t = false;
                        }
                    }

                    UNLOCK_MG();
                    return ret;
                }

                /* Handle the case of unmapping the first N pages */
                if(mce->start == addr) {
                    unmap_bottom_guard_page(mce);
                    mce->start += length;
                    ret = g_real_munmap(addr, length);

                    /* If the unmapping succeeded remap the bottom guard page */
                    if(ret == 0) {
                        void *p = allocate_guard_page(mce->start - g_page_size);

                        if(p == MAP_FAILED) {
                            mce->guarded_b = false;
                        }
                    }

                    UNLOCK_MG();
                    return ret;
                }
            } else {
#if MPK_SUPPORT
                if(mce->pkey) {
                    /* This is a full unmapping so we call pkey_free */
                    g_real_pkey_set(mce->pkey, 0);
                    g_real_pkey_free(mce->pkey);
                }
#endif
                ret = g_real_munmap(addr, length);

                /* Continue tracking a failed unmapping */
                if(ret) {
                    UNLOCK_MG();
                    return ret;
                }

                unmap_guard_pages(mce);
                LOG("Deleting cache entry for %p", mce->start);
                vector_delete_at(&g_map_cache_vector, mce->cache_index);
                UNLOCK_MG();
                return ret;
            }
        }
    }

    UNLOCK_MG();
    return g_real_munmap(addr, length);
}

/* Hook mprotect in libc */
int mprotect(void *addr, size_t len, int prot) {
    LOCK_MG();
    mapguard_cache_entry_t *mce = NULL;

    /* Disallow RWX mappings */
    if(g_mapguard_policy.disallow_rwx && (prot & PROT_WRITE) && (prot & PROT_EXEC)) {
        SYSLOG("Disallowing RWX mprotect");
        MAYBE_PANIC();
        UNLOCK_MG();
        return ERROR;
    }

    /* Disallow transition to/from X (requires the mapping cache) */
    if(g_mapguard_policy.use_mapping_cache) {
        mce = get_cache_entry(addr);
#if MPK_SUPPORT
        if(mce != NULL && mce->xom_enabled == 0) {
#else
        if(mce != NULL) {
#endif
            if(g_mapguard_policy.disallow_transition_to_x && (prot & PROT_EXEC) && (mce->immutable_prot & PROT_WRITE)) {
                SYSLOG("Cannot allow mapping %p to be set PROT_EXEC, it was previously PROT_WRITE", addr);
                MAYBE_PANIC();
                errno = EINVAL;
                UNLOCK_MG();
                return ERROR;
            }

            if(g_mapguard_policy.disallow_transition_from_x && (prot & PROT_WRITE) && (mce->immutable_prot & PROT_EXEC)) {
                SYSLOG("Cannot allow mapping %p to transition from PROT_EXEC to PROT_WRITE", addr);
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

    LOCK_MG();
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

    if((__flags & MAP_FIXED) || (__flags & MAP_FIXED_NOREPLACE)) {
        va_list vl;
        va_start(vl, __flags);
        new_address = va_arg(vl, void *);

        if(g_mapguard_policy.disallow_static_address) {
            SYSLOG("Attempted mremap with MREMAP_FIXED at %p", new_address);
            MAYBE_PANIC();
            errno = EINVAL;
            UNLOCK_MG();
            return NULL;
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
            }

            mce->start = map_ptr;
            mce->size = __new_len;

            /* Best effort guard page creation */
            void *ptr = g_real_mmap(map_ptr - g_page_size, g_page_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

            if(ptr != MAP_FAILED) {
                mce->guarded_b = true;
                ptr = g_real_mmap(map_ptr + __new_len, g_page_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

                if(ptr != MAP_FAILED) {
                    mce->guarded_t = true;
                }
            }

#if MPK_SUPPORT
            /* If this mapping had previously utilized MPK
             * support we need to setup that up again. We
             * cheat and reuse the existing pkey and assume
             * the desired access rights are the same */
            if(mce->pkey) {
                int32_t ret = g_real_pkey_mprotect(mce->start, mce->size, mce->current_prot, mce->pkey);

                if(ret) {
                    LOG("Failed to call pkey_mprotect for address %p", mce->start);
                }
            }
#endif
        }
    }

    UNLOCK_MG();
    return map_ptr;
}
