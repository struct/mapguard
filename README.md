# Map Guard

Map Guard is a proof of concept memory proxy that aims to mitigate memory safety exploits by intercepting, modifying, and logging `mmap` based page allocations. It enforces a simple set of allocation security policies configurable via environment variables. It works transparently on open and closed source programs with no source modifications in the target required. It also ships with an API for using Intel MPK extensions if your hardware supports it. Map Guard has only been tested on 64 bit Linux but should work on 32 bit programs and Mac OS with minor modifications.

## Implementation

Map Guard uses the dynamic linker interface via `dlsym` to hook libc functions. When calls to those functions are intercepted Map Guard will inspect their arguments and then consultits policies for whether that behavior should be allowed, denied, or logged.

The library requires hooking `mmap`, `munmap`, `mprotect`, and `mremap`. Enabling all protections may introduce some performance and memory overhead, especially if guard pages are enabled.

## Configuration

The following functionality can be enabled/disabled via environment variables:

* `MG_DISALLOW_RWX` - Disallows PROT_READ, PROT_WRITE, PROT_EXEC mappings
* `MG_DISALLOW_TRANSITION_TO_X` - Disallows RW allocations to ever transition to PROT_EXEC
* `MG_DISALLOW_TRANSITION_FROM_X` - Disallows R-X allocations to ever transition to PROT_WRITE
* `MG_DISALLOW_STATIC_ADDRESS` - Disallows page allocations at a set address (enforces ASLR)
* `MG_ENABLE_GUARD_PAGES` - Force guard page allocations on either side of all mappings
* `MG_PANIC_ON_VIOLATION` - Instructs Map Guard to abort the process when these policies are violated
* `MG_POISON_ON_ALLOCATION` - Fill all allocated pages with a byte pattern 0xde
* `MG_USE_MAPPING_CACHE` - Enable the mapping cache, required for guard pages and other protections
* `MG_ENABLE_SYSLOG` - Enable logging of policy violations to syslog

## MPK API

```
void *memcpy_xom(size_t allocation_size, void *src, size_t src_size) - Uses mmap to allocate allocation_size bytes of memory, copies src_size instructions from src and marks the memory execute only

int free_xom(void *addr, size_t length) - Free the memory allocated with memcpy_xom()

int32_t protect_mapping(void *addr) - Protects a single page, or range of pages if allocated via MapGuard

int32_t unprotect_mapping(void *addr, int new_prot) - Undoes the protection provided by protect_mapping()

int32_t protect_segments() - Marks all ELF PF_X segments as execute only

int32_t unprotect_segments() - Undoes the protection provided by protect_segments()

int32_t protect_code() - Uses a heuristic to find all .text pages for all loaded ELF objects and marks them execute only

int32_t unprotect_code() - Undoes the protection provided by protect_code()
```

## Testing

You can test Map Guard by running `./run_tests.sh`:

```
# ./run_tests.sh 
rm -rf ../build/
mkdir -p ../build/
clang -Wall -fPIC -shared -ldl -DDEBUG -ggdb mapguard.c vector.c -o ../build/mapguard.so
mkdir -p ../build/
clang -Wall -fPIE -fPIC  -DDEBUG -ggdb mapguard_test.c vector.c -o ../build/mapguard_test
[LOG][67059](map_guard_pages) Successfully allocated bottom guard page: [(guard) 0x7fb9e2516000 | 0x7fb9e2517000]
[LOG][67059](map_guard_pages) Failed to map top guard page @ 0x7fb9e2518000. Mapped @ 0x7fb9e2515000
[LOG][67059](map_memory) Successfully mmapped RW memory @ 0x7fb9e2517000
[LOG][67059](map_rw_memory) Test passed
[LOG][67059](munmap) Found mapguard cache entry for mapping 0x7fb9e2517000
[LOG][67059](munmap) Unmapped guard pages 0x7fb9e2516000 and 0x7fb9e2515000
[LOG][67059](munmap) Deleting cache entry for 0x7fb9e2517000
[LOG][67059](unmap_memory) Successfully munmapped memory @ 0x7fb9e2517000
[LOG][67059](mmap) Disallowing RWX memory allocation
[LOG][67059](map_memory) Failed to map RWX memory
[LOG][67059](map_rwx_memory) Test passed
[LOG][67059](map_guard_pages) Successfully allocated bottom guard page: [(guard) 0x7fb9e2516000 | 0x7fb9e2517000]
[LOG][67059](map_guard_pages) Failed to map top guard page @ 0x7fb9e2518000. Mapped @ 0x7fb9e2515000
[LOG][67059](map_memory) Successfully mmapped RW memory @ 0x7fb9e2517000
[LOG][67059](mprotect) Cannot allow mapping 0x7fb9e2517000 to be set PROT_EXEC
[LOG][67059](map_rw_then_x_memory) Test passed
[LOG][67059](munmap) Found mapguard cache entry for mapping 0x7fb9e2517000
[LOG][67059](munmap) Unmapped guard pages 0x7fb9e2516000 and 0x7fb9e2515000
[LOG][67059](munmap) Deleting cache entry for 0x7fb9e2517000
[LOG][67059](unmap_memory) Successfully munmapped memory @ 0x7fb9e2517000
[LOG][67059](map_guard_pages) Successfully allocated bottom guard page: [(guard) 0x7fb9e2516000 | 0x7fb9e2517000]
[LOG][67059](map_guard_pages) Failed to map top guard page @ 0x7fb9e2518000. Mapped @ 0x7fb9e2515000
[LOG][67059](map_memory) Successfully mmapped RW memory @ 0x7fb9e2517000
[LOG][67059](map_guard_pages) Successfully allocated bottom guard page: [(guard) 0x7fb9e2512000 | 0x7fb9e2513000]
[LOG][67059](map_guard_pages) Failed to map top guard page @ 0x7fb9e2515000. Mapped @ 0x7fb9e2515000
[LOG][67059](remap_memory) Successfully remapped Remap memory 0x7fb9e2517000 @ 0x7fb9e2513000
[LOG][67059](map_then_mremap) Test passed
[LOG][67059](munmap) Found mapguard cache entry for mapping 0x7fb9e2513000
[LOG][67059](munmap) Unmapped guard pages 0x7fb9e2512000 and 0x7fb9e2515000
[LOG][67059](munmap) Deleting cache entry for 0x7fb9e2513000
[LOG][67059](unmap_remapped_memory) Successfully munmapped remapped memory @ 0x7fb9e2513000
[LOG][67059](mmap) Disallowing memory allocation at static address 0x7f3bffaaa000
[LOG][67059](map_static_address) Test passed
[LOG][67059](map_guard_pages) Successfully allocated bottom guard page: [(guard) 0x7fb9e2516000 | 0x7fb9e2517000]
[LOG][67059](map_guard_pages) Failed to map top guard page @ 0x7fb9e2518000. Mapped @ 0x7fb9e2515000
[LOG][67059](map_memory) Successfully mmapped Poison Bytes memory @ 0x7fb9e2517000
[LOG][67059](check_poison_bytes) Test passed
[LOG][67059](munmap) Found mapguard cache entry for mapping 0x7fb9e2517000
[LOG][67059](munmap) Unmapped guard pages 0x7fb9e2516000 and 0x7fb9e2515000
[LOG][67059](munmap) Deleting cache entry for 0x7fb9e2517000
[LOG][67059](unmap_memory) Successfully munmapped memory @ 0x7fb9e2517000
[LOG][67059](map_guard_pages) Successfully allocated bottom guard page: [(guard) 0x7fb9e2516000 | 0x7fb9e2517000]
[LOG][67059](map_guard_pages) Failed to map top guard page @ 0x7fb9e2518000. Mapped @ 0x7fb9e2515000
[LOG][67059](map_memory) Successfully mmapped R-X memory @ 0x7fb9e2517000
[LOG][67059](mprotect) Cannot allow mapping 0x7fb9e2517000 to transition from PROT_EXEC to PROT_WRITE
[LOG][67059](check_x_to_w) Test passed
[LOG][67059](munmap) Found mapguard cache entry for mapping 0x7fb9e2517000
[LOG][67059](munmap) Unmapped guard pages 0x7fb9e2516000 and 0x7fb9e2515000
[LOG][67059](munmap) Deleting cache entry for 0x7fb9e2517000
[LOG][67059](unmap_memory) Successfully munmapped memory @ 0x7fb9e2517000
```

Or run your own program with the library:

```
MG_PANIC_ON_VIOLATION=0         \
MG_USE_MAPPING_CACHE=1          \
MG_DISALLOW_RWX=1               \
MG_DISALLOW_STATIC_ADDRESS=1    \
MG_ENABLE_GUARD_PAGES=1         \
MG_DISALLOW_X_TRANSITION=1      \
MG_POISON_ON_ALLOCATION=1       \
LD_PRELOAD=build/mapguard.so ./your_program
```

## Who

Copyright Chris Rohlf - 2022

chris.rohlf@gmail.com
