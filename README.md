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

## Compiling

`make library` - Compiles the library

`make tests` - Compiles a debug version of the library

`make perf_tests` - Compiles the performance tests

`make format` - Run clang format on the code base

Now run your own program with the library:

```
MG_PANIC_ON_VIOLATION=0         \
MG_USE_MAPPING_CACHE=1          \
MG_PREVENT_RWX=1               \
MG_PREVENT_STATIC_ADDRESS=1    \
MG_ENABLE_GUARD_PAGES=1         \
MG_PREVENT_TRANSITION_TO_X=1   \
MG_PREVENT_TRANSITION_FROM_X=1 \
MG_POISON_ON_ALLOCATION=1       \
LD_PRELOAD=build/libmapguard.so ./your_program
```

## Testing

You can test MapGuard by running `./run_tests.sh`:

```
# ./run_tests.sh 
Running mapguard_test test... Succeeded
Running mapguard_thread_test test... Succeeded

# ./run_perf_test.sh
================================================================
Running baseline performance (no MapGuard)...
================================================================
test_name,iterations,time_ms,ops_per_sec
simple_alloc_free,10000,8.28,1207522.82
alloc_write_free,10000,27.56,362884.76
batch_alloc_then_free,10000,7.53,1327830.27
varied_sizes,1000,0.75,1325820.35
mprotect_transitions,1000,1.29,777756.17
large_allocations,1000,0.74,1347180.55
partial_munmap,1000,1.36,734686.38

================================================================
Running with MapGuard (no config)...
================================================================
test_name,iterations,time_ms,ops_per_sec
simple_alloc_free,10000,8.00,1249934.85
alloc_write_free,10000,26.70,374585.62
batch_alloc_then_free,10000,7.58,1319130.69
varied_sizes,1000,0.81,1228689.91
mprotect_transitions,1000,1.33,753130.01
large_allocations,1000,0.83,1198442.98
partial_munmap,1000,1.31,764696.12

================================================================
Running with MapGuard (cache enabled)...
================================================================
test_name,iterations,time_ms,ops_per_sec
simple_alloc_free,10000,8.40,1190452.52
alloc_write_free,10000,27.73,360684.77
batch_alloc_then_free,10000,12.23,817661.49
varied_sizes,1000,0.85,1170561.32
mprotect_transitions,1000,1.46,685674.95
large_allocations,1000,0.84,1190239.56
partial_munmap,1000,1.39,721478.86

================================================================
Running with MapGuard (full protection)...
================================================================
test_name,iterations,time_ms,ops_per_sec
simple_alloc_free,10000,38.66,258667.52
alloc_write_free,10000,38.82,257607.74
batch_alloc_then_free,10000,56.12,178201.50
varied_sizes,1000,5.17,193604.62
mprotect_transitions,1000,4.84,206417.86
large_allocations,1000,97.63,10243.05
partial_munmap,1000,6.01,166516.33

================================================================
Performance Summary
================================================================
Test                           Baseline    Minimal   Cache        Full        Overhead %  
====================================================================================================
simple_alloc_free             1207523     1249935     1190453      258668        78.6%
alloc_write_free               362885      374586      360685      257608        29.0%
batch_alloc_then_free         1327830     1319131      817661      178202        86.6%
varied_sizes                  1325820     1228690     1170561      193605        85.4%
mprotect_transitions           777756      753130      685675      206418        73.5%
large_allocations             1347181     1198443     1190240       10243        99.2%
partial_munmap                 734686      764696      721479      166516        77.3%

# ./run_fuzz_tests
...
(see if anything crashes!)

```

## Who

MapGuard is written and maintained by Chris Rohlf - chris.rohlf@gmail.com
