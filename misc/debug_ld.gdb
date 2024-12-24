set pagination off
set breakpoint pending on
set logging enabled off
set verbose off
set trace-commands off

set environ MG_USE_MAPPING_CACHE=1
break main
r
break munmap
c

# Break just before the call to
# the unmap_guard_pages
break *munmap+604
c
# We need the second 'c'
# because other it is on the plt given
# it is the first call
c

# This is the PLT stub break
# for the call to unmap_guard_pages
break *0x7ffff7fa4120

# This continues and should stop in the 
# PLT stub
c
disas
