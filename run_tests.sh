## Make and run the unit tests
set +x
cd src/ &&
make tests &&
cd ../ &&
MG_PANIC_ON_VIOLATION=0         \
MG_USE_MAPPING_CACHE=1          \
MG_DISALLOW_RWX=1               \
MG_DISALLOW_TRANSITION_FROM_X=1 \
MG_DISALLOW_STATIC_ADDRESS=1    \
MG_ENABLE_GUARD_PAGES=1         \
MG_DISALLOW_X_TRANSITION=1      \
MG_POISON_ON_ALLOCATION=1       \
MG_ENABLE_SYSLOG=1              \
LD_LIBRARY_PATH=build/          \
LD_PRELOAD=build/libmapguard.so build/mapguard_test

MG_PANIC_ON_VIOLATION=0         \
MG_USE_MAPPING_CACHE=1          \
MG_DISALLOW_RWX=1               \
MG_DISALLOW_TRANSITION_FROM_X=1 \
MG_DISALLOW_STATIC_ADDRESS=1    \
MG_ENABLE_GUARD_PAGES=1         \
MG_DISALLOW_X_TRANSITION=1      \
MG_POISON_ON_ALLOCATION=1       \
MG_ENABLE_SYSLOG=1              \
LD_LIBRARY_PATH=build/          \
LD_PRELOAD=build/libmapguard_mpk.so build/mapguard_test_with_mpk

MG_PANIC_ON_VIOLATION=0         \
MG_USE_MAPPING_CACHE=1          \
MG_DISALLOW_RWX=1               \
MG_DISALLOW_TRANSITION_FROM_X=1 \
MG_DISALLOW_STATIC_ADDRESS=1    \
MG_ENABLE_GUARD_PAGES=1         \
MG_DISALLOW_X_TRANSITION=1      \
MG_POISON_ON_ALLOCATION=1       \
MG_ENABLE_SYSLOG=1              \
LD_LIBRARY_PATH=build/          \
LD_PRELOAD=build/libmapguard_mpk.so build/mapguard_thread_test
