file build/mapguard_test
set env MG_PANIC_ON_VIOLATION=0
set env MG_USE_MAPPING_CACHE=1
set env MG_DISALLOW_RWX=1
set env MG_DISALLOW_TRANSITION_FROM_X=1
set env MG_DISALLOW_STATIC_ADDRESS=1
set env MG_ENABLE_GUARD_PAGES=1
set env MG_DISALLOW_X_TRANSITION=1
set env MG_POISON_ON_ALLOCATION=1
set env MG_ENABLE_SYSLOG=1
set env LD_LIBRARY_PATH=build/
set env LD_PRELOAD=build/libmapguard.so
r
i r
x/i $rip
bt
info locals
