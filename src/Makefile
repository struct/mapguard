## Map Guard Makefile

CC = clang
CFLAGS = -Wall
ENABLE_MPK = -DMPK_SUPPORT=1
EXE_CFLAGS = -fPIE -pie
DEBUG_FLAGS = -DDEBUG -ggdb
LIBRARY = -fPIC -shared -ldl
ASAN = -fsanitize=address
TEST_FLAGS = -DVECTOR_UNIT_TEST=1

VECTOR_SRC = ../vector_t/vector.c

all: library library_mpk test

## Build the library
library: clean
	mkdir -p ../build/
	$(CC) $(CFLAGS) $(LIBRARY) mapguard.c mapguard_mpk.c $(VECTOR_SRC) -o ../build/libmapguard.so

## Build a debug version of the library
library_debug: clean
	mkdir -p ../build/
	$(CC) $(CFLAGS) $(LIBRARY) $(DEBUG_FLAGS) mapguard.c mapguard_mpk.c $(VECTOR_SRC) -o ../build/libmapguard.so

## Build the library with MPK support
library_mpk: clean
	mkdir -p ../build/
	$(CC) $(CFLAGS) $(LIBRARY) $(ENABLE_MPK) mapguard.c mapguard_mpk.c $(VECTOR_SRC) -o ../build/libmapguard_mpk.so

## Build a debug version of the library with MPK support
library_mpk_debug: clean
	mkdir -p ../build/
	$(CC) $(CFLAGS) $(LIBRARY) $(ENABLE_MPK) $(DEBUG_FLAGS) mapguard.c mapguard_mpk.c $(VECTOR_SRC) -o ../build/libmapguard_mpk.so

## Build a debug version of the unit test
tests: clean library_debug library_mpk_debug
	mkdir -p ../build/
	$(CC) $(CFLAGS) $(EXE_CFLAGS) $(DEBUG_FLAGS) tests/mapguard_test.c $(VECTOR_SRC) -o ../build/mapguard_test -L../build/ -lmapguard -ldl
	$(CC) $(CFLAGS) $(EXE_CFLAGS) $(DEBUG_FLAGS) $(ENABLE_MPK) tests/mapguard_test.c $(VECTOR_SRC) -o ../build/mapguard_test_with_mpk -L../build/ -lmapguard_mpk -ldl
	$(CC) $(CFLAGS) $(EXE_CFLAGS) $(DEBUG_FLAGS) $(ENABLE_MPK) tests/mapguard_thread_test.c $(VECTOR_SRC) -o ../build/mapguard_thread_test -L../build/ -lmapguard_mpk -lpthread -ldl

clean:
	rm -rf ../build/
