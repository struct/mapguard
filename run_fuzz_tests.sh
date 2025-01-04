#!/usr/bin/env bash
## Copyright Chris Rohlf - 2025

make tests

tests=("mapguard_test" "mapguard_test_with_mpk" "mapguard_thread_test")

export MG_USE_MAPPING_CACHE=1

while true; do
  # Randomize environment variables
  env_vars=(
    MG_PANIC_ON_VIOLATION
    MG_PREVENT_RWX
    MG_PREVENT_TRANSITION_FROM_X
    MG_PREVENT_STATIC_ADDRESS
    MG_ENABLE_GUARD_PAGES
    MG_PREVENT_X_TRANSITION
    MG_POISON_ON_ALLOCATION
    MG_ENABLE_SYSLOG
  )

  for var in "${env_vars[@]}"; do
    export "$var=$((RANDOM % 2))"
  done

  # Ensure correct library path
  export LD_LIBRARY_PATH=build/

  # Run each test until we detect a segfault
  for t in "${tests[@]}"; do
    ./build/$t
    ret=$?
    if [ "$ret" -eq 139 ]; then
      echo "Segmentation fault detected in $t. Exiting."
      for var in "${env_vars[@]}"; do
        env | grep $var
      done
      echo build/$t
      exit 1
    fi
  done
done