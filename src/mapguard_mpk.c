/* Reference implementation of map guard
 * Copyright Chris Rohlf - 2019 */

#include "mapguard.h"

#if MPK_SUPPORT

/* Memory Protection Keys is a feature on Intel x64 Skylake and newer processors
 * that allows a program to set permission bits on a per-page mapping. The advantage
 * of MPK over mprotect() is that its a lot faster. This feature of MapGuard
 * has only been tested on AWS EC2 C5 instances and it may not even work there
 * depending on your kernel version and program design.
 *
 * To know if your kernel supports MPK try the following:
 * cat /proc/cpuinfo | grep -E 'pku|ospke'
 *
 * The Map Guard APIs that work with MPK always works terms of page ranges.
 * This means for API functions like protect_mapping which take a start
 * and end pointer we may end up protecting an entire region of memory
 * and not just the page represented by the start pointer. Theres no easy
 * way to implement this except for with explicit documentation detailing
 * the implicit behavior.
 */

/* Free XOM allocated with memcpy_xom */
int free_xom(void *addr, size_t length) {
    mapguard_cache_entry_t *mce = (mapguard_cache_entry_t *) vector_for_each(&g_map_cache_vector, (vector_for_each_callback_t *) is_mapguard_entry_cached, (void *) addr);

    if(mce != NULL) {
        LOG("Found mapguard cache entry for mapping %p", mce->start);
        g_real_munmap(mce->start, mce->size);
        vector_delete_at(&g_map_cache_vector, mce->cache_index);
        free(mce);
    } else {
        return ERROR;
    }

    return OK;
}

/* memcpy_xom - Allocates writeable memory, copies src_size bytes from src
 * into those pages, and then marks the allocation execute only. Upon
 * failure it returns MAP_FAILED. Upon success it returns a pointer to the
 * Execute Only memory region */
void *memcpy_xom(size_t allocation_size, void *src, size_t src_size) {

    if(g_mapguard_policy.use_mapping_cache == 0) {
        LOG("Cannot allocate XOM memory without MG_USE_MAPPING_CACHE enabled");
        return MAP_FAILED;
    }

    if(src == NULL || src_size == 0) {
        LOG("XOM allocation failed, src is %p and src_size = %ld", src, src_size);
        return MAP_FAILED;
    }

    allocation_size = ROUND_UP_PAGE((uint64_t) allocation_size);

    if(src_size > allocation_size) {
        LOG("XOM allocation failed, src size larger than allocation size")
        return MAP_FAILED;
    }

    void *map_ptr = g_real_mmap(0x0, allocation_size, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);

    if(map_ptr == MAP_FAILED) {
        LOG("XOM mmap failed");
        return MAP_FAILED;
    }

    memcpy(map_ptr, src, src_size);

    mapguard_cache_entry_t *mce = (mapguard_cache_entry_t *) malloc(sizeof(mapguard_cache_entry_t));
    memset(mce, 0x0, sizeof(mapguard_cache_entry_t));

    mce->start = map_ptr;
    mce->size = allocation_size;
    mce->immutable_prot |= PROT_EXEC;
    mce->current_prot = PROT_EXEC;
    mce->xom_enabled = 1;

    /* We use -1 as a stand in for the kernels execute_only_pkey */
    mce->pkey = -1;
    mce->pkey_access_rights = PKEY_DISABLE_ACCESS;

    int32_t ret = g_real_mprotect(map_ptr, allocation_size, PROT_EXEC);

    if(ret != 0) {
        LOG("XOM mprotect failed, unmapping memory");
        g_real_munmap(map_ptr, allocation_size);
        free(mce);
        return MAP_FAILED;
    }

    mce->cache_index = vector_push(&g_map_cache_vector, mce);

    return map_ptr;
}

/* addr - Address within a page range to protect
 *
 * This function derives the base page from addr and
 * then determines if Map Guard is currently tracking
 * it. If so we check for an existing pkey or alloc a new
 * one. A -1 return value means we are out of pkeys or
 * the value of start was bad.
 *
 * If this function detects we are tracking an allocation
 * of pages this address falls within the entire range will
 * be protected with MPK, not just the page its on. If we
 * detect the mapping already has a pkey associated with
 * it that key is free'd and a new one allocated. This can
 * have unintended side effects so it is not recommended. */
int32_t protect_mapping(void *addr) {
    if(addr == NULL) {
        return ERROR;
    }

    int new_mce = 0;
    mapguard_cache_entry_t *mce = get_cache_entry(addr);

    if(mce == NULL) {
        /* We aren't currently tracking these pages, so lets
         * start doing that. We don't allocate guard pages
         * because no r/w operations will take place here */
        mce = new_mapguard_cache_entry();
        mce->start = get_base_page(addr);
        /* We only know a single address, so we default to 1 page */
        mce->size = g_page_size;
        mce->immutable_prot |= PROT_NONE;
        mce->current_prot = PROT_NONE;
        mce->cache_index = vector_push(&g_map_cache_vector, mce);
        new_mce = 1;
    }

    mce->pkey_access_rights = PKEY_DISABLE_ACCESS;

    /* If there an existing key then we free it and allocate a new one */
    if(mce->pkey != 0) {
        g_real_pkey_set(mce->pkey, 0);
        g_real_pkey_free(mce->pkey);
    } else if(new_mce) {
        goto fail;
    }

    mce->pkey = g_real_pkey_alloc(0, mce->pkey_access_rights);

    if(mce->pkey == -1) {
        LOG("Failed to allocate protection key for address %p", mce->start);
        goto fail;
    }

    int32_t ret = g_real_pkey_mprotect(mce->start, mce->size, PROT_NONE, mce->pkey);

    if(ret) {
        LOG("Failed to call pkey_mprotect for address %p", mce->start);
        goto fail;
    }

    return OK;

    fail:

    if(new_mce) {
        if(mce->pkey != 0) {
            g_real_pkey_set(mce->pkey, 0);
            g_real_pkey_free(mce->pkey);
        }

        vector_delete_at(&g_map_cache_vector, mce->cache_index);
        free(mce);
    }

    return ERROR;
}

int32_t unprotect_mapping(void *addr, int new_prot) {
    if(addr == NULL) {
        return ERROR;
    }

    mapguard_cache_entry_t *mce = get_cache_entry(addr);

    if(mce != NULL && mce->pkey) {
        mce->immutable_prot |= new_prot;
        mce->current_prot = new_prot;
        mce->pkey_access_rights = 0;
        g_real_pkey_set(mce->pkey, mce->pkey_access_rights);
        g_real_pkey_mprotect(get_base_page(addr), mce->size, new_prot, mce->pkey);
        g_real_pkey_free(mce->pkey);
        mce->pkey = 0;
    } else {
        return ERROR;
    }

    return OK;
}

/* Map Guard library implementation */
static int32_t map_guard_protect_segments_callback(struct dl_phdr_info *info, size_t size, void *data) {
    const char *object_name = "unknown_object";

    if(strlen(info->dlpi_name) != 0) {
        object_name = info->dlpi_name;
    }

    if(strlen(object_name) >= strlen("linux-vdso") && strncmp(object_name, "linux-vdso", 10) == 0) {
        LOG("Skipping VDSO (%s)", object_name);
        return 0;
    }

    void *load_address = (void *) info->dlpi_addr;
    int32_t ret = OK;

    for(uint32_t i = 0; i < info->dlpi_phnum; i++) {
        if(info->dlpi_phdr[i].p_type == PT_LOAD && (info->dlpi_phdr[i].p_flags & PF_X)) {
            ret |= g_real_mprotect(load_address, info->dlpi_phdr[i].p_memsz, (int32_t) data);
        }
    }

    return ret;
}

static int32_t map_guard_protect_code_callback(struct dl_phdr_info *info, size_t size, void *data) {
    const char *object_name = "unknown_object";

    if(info->dlpi_addr == 0) {
        return 0;
    }

    if(strlen(info->dlpi_name) != 0) {
        object_name = info->dlpi_name;
    }

    if(strlen(object_name) >= strlen("linux-vdso") && strncmp(object_name, "linux-vdso", 10) == 0) {
        LOG("Skipping VDSO (%s)", object_name);
        return 0;
    }

    void *load_address = (void *) info->dlpi_addr;
    ElfW(Phdr*) phdr = NULL;

    /* Marking an entire PF_X load segment as execute-only can
     * have unintended side effects. This is especially true when
     * the linker has grouped read-only data into the same segment
     * this is common unfortunately. Its a lot safer to only mark
     * the .text execute-only but locating its exact address and
     * size without touching the object on disk is difficult. The
     * approach taken here is a simple heuristic that uses the
     * symbol table to approximate how large the .text is */

    /* First iterate through the program headers for the
     * PT_DYNAMIC segment. We need it to find symbols */
    for(uint32_t i = 0; i < info->dlpi_phnum; i++) {
        if(info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            phdr = (ElfW(Phdr*)) &info->dlpi_phdr[i];
            LOG("Found PT_DYNAMIC segment @ %p %lx for object %s" , phdr, info->dlpi_phdr[i].p_vaddr, object_name);
            break;
        }
    }

    ElfW(Dyn*) dyn = (ElfW(Dyn*))(phdr->p_vaddr + load_address);
    ElfW(Sym*) sym = NULL;
    ElfW(Word) symbol_count = 0;
    ElfW(Word*) dt_hash = NULL;
    ElfW(Word*) dt_gnu_hash = NULL;

    for(uint32_t i = 0; i < (phdr->p_filesz/sizeof(ElfW(Dyn))); i++) {
        if(dyn[i].d_tag == DT_HASH) {
            dt_hash = (ElfW(Word*)) dyn[i].d_un.d_ptr;

            if(dt_hash == NULL) {
                continue;
            }

            symbol_count = dt_hash[1];
            LOG("DT_HASH Number of symbols: %d", symbol_count);
        }

        if(dyn[i].d_tag == DT_GNU_HASH) {
            dt_gnu_hash = (ElfW(Word *)) dyn[i].d_un.d_ptr;
            const uint32_t nbuckets = dt_gnu_hash[0];
            const uint32_t bloom_size = dt_gnu_hash[2];
            const uint64_t* bloom = (void*) &dt_gnu_hash[4];
            const uint32_t* buckets = (void*) &bloom[bloom_size];

            /* This is good enough to get the size of the dynsym but
             * it won't tell us total number of symbols including the
             * the symtab. If we want the symtab for the main exe we
             * to parse it from disk and thats too slow here */
            for(uint32_t index = 0; index < nbuckets; index++) {
                if(buckets[index] > symbol_count) {
                    symbol_count = buckets[index];
                }
            }

            LOG("DT_GNU_HASH Number of symbols: %d", symbol_count);
        }

        if(dyn[i].d_tag == DT_SYMTAB) {
            sym = (ElfW(Sym*)) dyn[i].d_un.d_ptr;
        }
    }

    if(symbol_count == 0 || sym == NULL) {
        LOG_ERROR("Cannot parse the symbol table to derive .text size");
        return OK;
    }

    void *text_start = 0;
    uint64_t text_size = 0;

    for(int i = 0; i < symbol_count; i++, sym++) {
        /* We only care about symbols of type STT_FUNC because
         * they likely point at executable code pages. Functions
         * with a size of 0 likely imported */
        if((sym->st_info & 0xf) != STT_FUNC || sym->st_size == 0) {
            continue;
        }

        void *addr = (void *)(load_address + sym->st_value);
        text_size += sym->st_size;

        if(addr < text_start || text_start == 0) {
            text_start = addr;
        }
    }

    text_start = (void *) ROUND_UP_PAGE((uint64_t) text_start);

    if(text_size <= g_page_size) {
        text_size = g_page_size;
    } else {
        text_size = ROUND_DOWN_PAGE(text_size);
    }

    LOG("text_start = %p | .text size %ld bytes", text_start, text_size);

    for(uint32_t i = 0; i < info->dlpi_phnum; i++) {
        if(info->dlpi_phdr[i].p_type == PT_LOAD && (info->dlpi_phdr[i].p_flags & PF_X)) {

            if(text_size > info->dlpi_phdr[i].p_memsz) {
                LOG("Estimated .text size (%ld bytes) is bigger than segment %d (%lx bytes)", text_size, i, info->dlpi_phdr[i].p_memsz);
                continue;
            }

            int32_t unprotected_exec = info->dlpi_phdr[i].p_memsz - text_size;
            LOG("An estimated %x bytes of this segment is still readable", unprotected_exec);

            LOG("mprotect(%p, %ld)", text_start, text_size);
            int ret = g_real_mprotect(text_start, text_size, (int32_t) data);

            /* Log the error but this is best effort so continue */
            if(ret != 0) {
                LOG_ERROR("Failed to mprotect code page %p for object %s", text_start, object_name);
            } else {
                LOG("Successfully marked .text range @ %p execute-only for object %s", text_start, object_name);
            }

            return OK;
        }
    }

    return OK;
}

/* Uses the dynamic linker dl_iterate_phdr API to locate all
 * currently mapped DSO's, parses their program headers to find
 * as much of the .text section as possible and marks it PROT_EXEC */
int32_t protect_code() {
    return dl_iterate_phdr(map_guard_protect_code_callback, (void *) PROT_EXEC);
}

/* Undoes the execute only protections put in place by protect_code() */
int32_t unprotect_code() {
    return dl_iterate_phdr(map_guard_protect_code_callback, (void *) (PROT_READ|PROT_EXEC));
}

/* Uses the dynamic linker dl_iterate_phdr API to locate all
 * currently mapped PT_LOAD segments with PF_X flags and then
 * uses mprotect to mark them execute only */
int32_t protect_segments() {
    return dl_iterate_phdr(map_guard_protect_segments_callback, (void *) PROT_EXEC);
}

/* Undoes the execute only protections put in place by protect_segments() */
int32_t unprotect_segments() {
    return dl_iterate_phdr(map_guard_protect_segments_callback, (void *) (PROT_READ|PROT_EXEC));
}

/* If we are in a process with code that utilizes MPK API
 * outside of MapGuard then things will break. Instead of
 * trying to coexist we just break those interfaces. */

/* Hook pkey_mprotect in libc */
int pkey_mprotect(void *addr, size_t len, int prot, int pkey) {
    /* No support for other pkey callers */
    return ERROR;
}

/* Hook pkey_alloc in libc */
int pkey_alloc(unsigned int flags, unsigned int access_rights) {
    /* No support for other pkey callers */
    return ERROR;
}

/* Hook pkey_free in libc */
int pkey_free(int pkey) {
    /* No support for other pkey callers */
    return ERROR;
}

/* Hook pkey_set in libc */
int pkey_set(int pkey, unsigned int access_rights) {
    /* No support for other pkey callers */
    return ERROR;
}

/* Hook pkey_get in libc */
int pkey_get(int pkey) {
    /* No support for other pkey callers */
    return ERROR;
}
#endif
