# MapGuard

MapGuard is a page allocation proxy and cache that aims to mitigate some memory safety exploits by intercepting, modifying, and logging `mmap` based page allocations. It enforces a simple set of allocation security policies configurable via environment variables. It works transparently on open and closed source programs with no source modifications in the target required. It can be used along side any mmap based memory allocator.

## Implementation

MapGuard uses the dynamic linker interface via `dlsym` to hook libc functions. When calls to those functions are intercepted MapGuard will inspect their arguments and then consult runtime policies for whether that behavior should be allowed, denied, or logged.

The library requires hooking `mmap`, `munmap`, `mprotect`, and `mremap`. Enabling all protections may introduce some performance and memory overhead, especially if guard pages are enabled.

## Performance

MapGuard can introduce performance overhead when allocating many raw pages. This is particulary true when `MG_USE_MAPPING_CACHE` is enabled because it has to manage metadata for each page allocation and tracking this data introduces CPU and memory overhead. Faster data structures are available for managing this metadata but they all rely on `malloc` which makes it easier to bypass the security controls the library introduces.

## Configuration

The following functionality can be enabled/disabled via environment variables:

* `MG_PREVENT_RWX` - Prevent PROT_READ, PROT_WRITE, PROT_EXEC mappings
* `MG_PREVENT_TRANSITION_TO_X` - Prevent RW- allocations to ever transition to PROT_EXEC
* `MG_PREVENT_TRANSITION_FROM_X` - Prevent R-X allocations to ever transition to PROT_WRITE
* `MG_PREVENT_STATIC_ADDRESS` - Prevent page allocations at a set address (enforces ASLR)
* `MG_ENABLE_GUARD_PAGES` - Force guard page allocations on either side of all mappings
* `MG_PANIC_ON_VIOLATION` - Abort the process when any policies are violated
* `MG_POISON_ON_ALLOCATION` - Fill all allocated pages with a byte pattern 0xde
* `MG_USE_MAPPING_CACHE` - Enable the mapping cache, required for guard pages and other protections
* `MG_ENABLE_SYSLOG` - Enable logging of policy violations to syslog

## Testing

You can test MapGuard by running `./run_tests.sh`:

```
# ./run_tests.sh 

...

```

Or run your own program with the library:

```
MG_PANIC_ON_VIOLATION=0         \
MG_USE_MAPPING_CACHE=1          \
MG_PREVENT_RWX=1               \
MG_PREVENT_STATIC_ADDRESS=1    \
MG_ENABLE_GUARD_PAGES=1         \
MG_PREVENT_TRANSITION_TO_X=1   \
MG_PREVENT_TRANSITION_FROM_X=1 \
MG_POISON_ON_ALLOCATION=1       \
LD_PRELOAD=build/mapguard.so ./your_program
```

## Who

MapGuard is written and maintained by Chris Rohlf - chris.rohlf@gmail.com
