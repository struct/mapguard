#!/usr/bin/env bash

## This runs all unit tests and reports the results to stdout
## Copyright Chris Rohlf - 2025

export MG_PANIC_ON_VIOLATION=0
export MG_USE_MAPPING_CACHE=1
export MG_PREVENT_RWX=1
export MG_PREVENT_TRANSITION_FROM_X=1
export MG_PREVENT_STATIC_ADDRESS=1
export MG_ENABLE_GUARD_PAGES=1
export MG_PREVENT_X_TRANSITION=1
export MG_POISON_ON_ALLOCATION=1
export MG_ENABLE_SYSLOG=0
export LD_LIBRARY_PATH=build/

tests=("mapguard_test" "mapguard_test_with_mpk" "mapguard_thread_test")
failure=0
succeeded=0

mmap_min_addr=`sysctl vm.mmap_min_addr |cut -f3 -d" "`

if [ $mmap_min_addr -ne "0" ]
then
	echo "vm.mmap_min_addr should be 0 for some of the tests to work"
fi

for t in "${tests[@]}"; do
    echo -n "Running $t test"
    echo -n "Running $t test" >> test_output.txt 2>&1
    $(build/$t >> test_output.txt 2>&1)
    ret=$?

    if [ $ret -ne 0 ]; then
        echo "... Failed"
        echo "... Failed" >> test_output.txt 2>&1
        failure=$((failure+1))
    else
        echo "... Succeeded"
        echo "... Succeeded" >> test_output.txt 2>&1
        succeeded=$((succeeded+1))
    fi
done

unset MG_PANIC_ON_VIOLATION
unset MG_USE_MAPPING_CACHE
unset MG_PREVENT_RWX
unset MG_PREVENT_TRANSITION_FROM_X
unset MG_PREVENT_STATIC_ADDRESS
unset MG_ENABLE_GUARD_PAGES
unset MG_PREVENT_X_TRANSITION
unset MG_POISON_ON_ALLOCATION
unset MG_ENABLE_SYSLOG
unset LD_LIBRARY_PATH
