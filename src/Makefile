## Map Guard Makefile

CC = clang
CFLAGS = -Wall
EXE_CFLAGS = -fPIE -fPIC
DEBUG_FLAGS = -DDEBUG -ggdb
LIBRARY = -fPIC -shared -ldl
ASAN = -fsanitize=address

all: library test

## Build the library
library: clean
	mkdir -p ../build/
	$(CC) $(CFLAGS) $(LIBRARY) mapguard.c vector.c -o ../build/mapguard.so

## Build a debug version of the library
library_debug: clean
	mkdir -p ../build/
	$(CC) $(CFLAGS) $(LIBRARY) $(DEBUG_FLAGS) mapguard.c vector.c -o ../build/mapguard.so

## Build the unit test
test: clean library
	mkdir -p ../build/
	$(CC) $(CFLAGS) $(EXE_CFLAGS) $(INCLUDE_DIR) mapguard_test.c vector.c -o ../build/mapguard_test

## Build a debug version of the unit test
debug_test: clean library_debug
	mkdir -p ../build/
	$(CC) $(CFLAGS) $(EXE_CFLAGS) $(INCLUDE_DIR) $(DEBUG_FLAGS) mapguard_test.c vector.c -o ../build/mapguard_test

## Build the vector tests
vector_test:
	mkdir -p ../build/
	$(CC) $(ASAN) $(EXE_CFLAGS) $(DEBUG_FLAGS) $(CFLAGS) -o ../build/vector_test vector.c -DVECTOR_UNIT_TEST=1

clean:
	rm -rf ../build/