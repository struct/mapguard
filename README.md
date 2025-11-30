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
simple_alloc_free,10000,8.47,1180504.02
alloc_write_free,10000,26.84,372601.38
batch_alloc_then_free,10000,7.34,1362606.67
varied_sizes,1000,0.76,1323043.58
mprotect_transitions,1000,1.31,764720.68
large_allocations,1000,0.80,1246040.71
partial_munmap,1000,1.32,755381.72

================================================================
Running with MapGuard (no config)...
================================================================
test_name,iterations,time_ms,ops_per_sec
simple_alloc_free,10000,8.22,1216705.32
alloc_write_free,10000,27.75,360331.68
batch_alloc_then_free,10000,7.49,1335589.05
varied_sizes,1000,0.82,1218522.52
mprotect_transitions,1000,1.39,717703.52
large_allocations,1000,0.82,1215744.87
partial_munmap,1000,1.37,731707.14

================================================================
Running with MapGuard (cache enabled)...
================================================================
test_name,iterations,time_ms,ops_per_sec
simple_alloc_free,10000,8.57,1166271.34
alloc_write_free,10000,27.52,363336.88
batch_alloc_then_free,10000,12.19,820263.26
varied_sizes,1000,0.86,1168907.07
mprotect_transitions,1000,1.47,681605.18
large_allocations,1000,0.86,1167712.74
partial_munmap,1000,1.45,691044.89

================================================================
Running with MapGuard (full protection)...
================================================================
test_name,iterations,time_ms,ops_per_sec
simple_alloc_free,10000,38.12,262334.37
alloc_write_free,10000,38.36,260671.51
batch_alloc_then_free,10000,62.45,160123.29
varied_sizes,1000,5.01,199401.79
mprotect_transitions,1000,4.64,215372.19
large_allocations,1000,97.27,10280.64
partial_munmap,1000,5.64,177332.48

================================================================
Performance Summary
================================================================
Test                           Baseline    Minimal   Cache        Full        Overhead %  
====================================================================================================
simple_alloc_free             1180504     1216705     1166271      262334        77.8%
alloc_write_free               372601      360332      363337      260672        30.0%
batch_alloc_then_free         1362607     1335589      820263      160123        88.2%
varied_sizes                  1323044     1218523     1168907      199402        84.9%
mprotect_transitions           764721      717704      681605      215372        71.8%
large_allocations             1246041     1215745     1167713       10281        99.2%
partial_munmap                 755382      731707      691045      177332        76.5%

Raw CSV files saved in /tmp/*_perf.csv

# ./run_fuzz_tests
...
(see if anything crashes!)

```

## Who

MapGuard is written and maintained by Chris Rohlf - chris.rohlf@gmail.com
