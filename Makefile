## Map Guard Makefile

CC = clang
CFLAGS = -Wall
ENABLE_MPK = -DMPK_SUPPORT=1
EXE_CFLAGS = -fPIE -pie
DEBUG_FLAGS = -DDEBUG -ggdb
LIBRARY = -fPIC -shared -ldl
ASAN = -fsanitize=address
TEST_FLAGS = -DVECTOR_UNIT_TEST=1
VECTOR_SRC = vector_t/vector.c
SRC_DIR = src
TESTS_SRC_DIR = src/tests
SRC_FILES = *.c

all: library library_mpk tests

## Build the library
library: clean
	@echo "make clean"
	mkdir -p build/
	$(CC) $(CFLAGS) $(LIBRARY) $(SRC_DIR)/$(SRC_FILES) $(VECTOR_SRC) -o build/libmapguard.so

## Build a debug version of the library
library_debug: clean
	@echo "make library_debug"
	mkdir -p build/
	$(CC) $(CFLAGS) $(LIBRARY) $(DEBUG_FLAGS) $(SRC_DIR)/$(SRC_FILES) $(VECTOR_SRC) -o build/libmapguard.so

## Build the library with MPK support
library_mpk: clean
	@echo "make library_mpk"
	mkdir -p build/
	$(CC) $(CFLAGS) $(LIBRARY) $(ENABLE_MPK) $(SRC_DIR)/$(SRC_FILES) $(VECTOR_SRC) -o build/libmapguard_mpk.so

## Build a debug version of the library with MPK support
library_mpk_debug: clean
	@echo "make library_mpk_debug"
	mkdir -p build/
	$(CC) $(CFLAGS) $(LIBRARY) $(ENABLE_MPK) $(DEBUG_FLAGS) $(SRC_DIR)/$(SRC_FILES) $(VECTOR_SRC) -o build/libmapguard_mpk.so

## Build a debug version of the unit test
tests: clean library_debug library_mpk_debug
	@echo "make tests"
	mkdir -p build/
	$(CC) $(CFLAGS) $(EXE_CFLAGS) $(DEBUG_FLAGS) $(TESTS_SRC_DIR)/mapguard_test.c $(VECTOR_SRC) -o build/mapguard_test -L../build/ -lmapguard -ldl
	$(CC) $(CFLAGS) $(EXE_CFLAGS) $(DEBUG_FLAGS) $(ENABLE_MPK) $(TESTS_SRC_DIR)/mapguard_test.c $(VECTOR_SRC) -o build/mapguard_test_with_mpk -L../build/ -lmapguard_mpk -ldl
	$(CC) $(CFLAGS) $(EXE_CFLAGS) $(DEBUG_FLAGS) $(ENABLE_MPK) $(TESTS_SRC_DIR)/mapguard_thread_test.c $(VECTOR_SRC) -o build/mapguard_thread_test -L../build/ -lmapguard_mpk -lpthread -ldl

format:
	clang-format $(SRC_DIR)/*.* $(SRC_DIR)/tests/*.* -i

clean:
	rm -rf build/*
