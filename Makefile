## Map Guard Makefile

CC = clang
SHELL := /bin/bash

## Support for multithreaded programs
THREADS = -DTHREAD_SUPPORT=1

CFLAGS = -Wall -std=c11 -O2
EXE_CFLAGS = -fPIE -pie
DEBUG_FLAGS = -DDEBUG -ggdb
LIBRARY = -fPIC -shared -ldl
ASAN = -fsanitize=address
TEST_FLAGS =
SRC = src
INCLUDE = include
TEST_SRC = tests
SRC_FILES = *.c
BUILD_DIR = build
STRIP = strip -s $(BUILD_DIR)/libmapguard.so

ifeq ($(THREADS), -DTHREAD_SUPPORT=1)
CFLAGS += -lpthread $(THREADS)
endif

all: library tests

## Build the library
library: clean
	@echo "make clean"
	mkdir -p $(BUILD_DIR)/
	$(CC) $(CFLAGS) $(LIBRARY) $(SRC)/$(SRC_FILES) -I $(INCLUDE) -o $(BUILD_DIR)/libmapguard.so
	$(STRIP)

## Build a debug version of the library
library_debug: clean
	@echo "make library_debug"
	mkdir -p $(BUILD_DIR)/
	$(CC) $(CFLAGS) $(LIBRARY) $(DEBUG_FLAGS) $(SRC)/$(SRC_FILES) -I $(INCLUDE)  -o $(BUILD_DIR)/libmapguard.so

## Build the unit tests
tests: clean library_debug
	@echo "make tests"
	mkdir -p $(BUILD_DIR)/
	$(CC) $(CFLAGS) $(EXE_CFLAGS) $(DEBUG_FLAGS) $(TEST_SRC)/mapguard_test.c -I $(INCLUDE)  -o $(BUILD_DIR)/mapguard_test -L build/ -ldl
	$(CC) $(CFLAGS) $(EXE_CFLAGS) $(DEBUG_FLAGS) $(TEST_SRC)/mapguard_thread_test.c -I $(INCLUDE)  -o $(BUILD_DIR)/mapguard_thread_test -L build/ -lpthread -ldl

perf_tests: clean library
	$(CC) $(CFLAGS) $(EXE_CFLAGS) -o build/mapguard_perf_test tests/mapguard_perf_test.c

format:
	clang-format $(INCLUDE)/*.* $(SRC)/*.* $(TEST_SRC)/*.* -i

clean:
	rm -rf build/* test_output.txt core
