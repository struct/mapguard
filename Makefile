## Map Guard Makefile

CC = clang
CFLAGS = -Wall
MPK = -DMPK_SUPPORT=1
EXE_CFLAGS = -fPIE -pie
DEBUG_FLAGS = -DDEBUG -ggdb
LIBRARY = -fPIC -shared -ldl
ASAN = -fsanitize=address
TEST_FLAGS = -DVECTOR_UNIT_TEST=1
VECTOR_SRC = vector_t/vector.c
SRC = src
INCLUDE = include
TEST_SRC = tests
SRC_FILES = *.c
BUILD_DIR = build
STRIP = strip -s $(BUILD_DIR)/libmapguard.so

all: library library_mpk tests

## Build the library
library: clean
	@echo "make clean"
	mkdir -p $(BUILD_DIR)/
	$(CC) $(CFLAGS) $(LIBRARY) $(SRC)/$(SRC_FILES) -I $(INCLUDE) $(VECTOR_SRC) -o $(BUILD_DIR)/libmapguard.so
	$(STRIP)

## Build a debug version of the library
library_debug: clean
	@echo "make library_debug"
	mkdir -p $(BUILD_DIR)/
	$(CC) $(CFLAGS) $(LIBRARY) $(DEBUG_FLAGS) $(SRC)/$(SRC_FILES) -I $(INCLUDE) $(VECTOR_SRC) -o $(BUILD_DIR)/libmapguard.so

## Build the library with MPK support
library_mpk: clean
	@echo "make library_mpk"
	mkdir -p $(BUILD_DIR)/
	$(CC) $(CFLAGS) $(LIBRARY) $(MPK) $(SRC)/$(SRC_FILES) -I $(INCLUDE) $(VECTOR_SRC) -o $(BUILD_DIR)/libmapguard_mpk.so

## Build a debug version of the library with MPK support
library_mpk_debug: clean
	@echo "make library_mpk_debug"
	mkdir -p $(BUILD_DIR)/
	$(CC) $(CFLAGS) $(LIBRARY) $(MPK) $(DEBUG_FLAGS) $(SRC)/$(SRC_FILES) -I $(INCLUDE) $(VECTOR_SRC) -o $(BUILD_DIR)/libmapguard_mpk.so

## Build a debug version of the unit test
tests: clean library_debug library_mpk_debug
	@echo "make tests"
	mkdir -p $(BUILD_DIR)/
	$(CC) $(CFLAGS) $(EXE_CFLAGS) $(DEBUG_FLAGS) $(TEST_SRC)/mapguard_test.c -I $(INCLUDE) $(VECTOR_SRC) -o $(BUILD_DIR)/mapguard_test -L build/ -lmapguard -ldl
	$(CC) $(CFLAGS) $(EXE_CFLAGS) $(DEBUG_FLAGS) $(MPK) $(TEST_SRC)/mapguard_test.c -I $(INCLUDE) $(VECTOR_SRC) -o $(BUILD_DIR)/mapguard_test_with_mpk -L build/ -lmapguard_mpk -ldl
	$(CC) $(CFLAGS) $(EXE_CFLAGS) $(DEBUG_FLAGS) $(MPK) $(TEST_SRC)/mapguard_thread_test.c -I $(INCLUDE) $(VECTOR_SRC) -o $(BUILD_DIR)/mapguard_thread_test -L build/ -lmapguard_mpk -lpthread -ldl

format:
	clang-format $(INCLUDE)/*.* $(SRC)/*.* $(TEST_SRC)/*.* -i

clean:
	rm -rf build/*
