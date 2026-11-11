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
DEMO_SRC = demo
SRC_FILES = *.c
BUILD_DIR = build
STRIP = strip -s $(BUILD_DIR)/libmapguard.so

UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
# $(error MacOS not supported, mapguard is Linux only)
endif

ifeq ($(THREADS), -DTHREAD_SUPPORT=1)
CFLAGS += -lpthread $(THREADS)
endif

all: library tests

## Build the library
library:
	@echo "make library"
	mkdir -p $(BUILD_DIR)/
	$(CC) $(CFLAGS) $(LIBRARY) $(SRC)/$(SRC_FILES) -I $(INCLUDE) -o $(BUILD_DIR)/libmapguard.so
	$(STRIP)

## Build a debug version of the library
library_debug:
	@echo "make library_debug"
	mkdir -p $(BUILD_DIR)/
	$(CC) $(CFLAGS) $(LIBRARY) $(DEBUG_FLAGS) $(SRC)/$(SRC_FILES) -I $(INCLUDE)  -o $(BUILD_DIR)/libmapguard.so

## Build the unit tests (depends on debug library)
tests: library_debug
	@echo "make tests"
	mkdir -p $(BUILD_DIR)/
	$(CC) $(CFLAGS) $(EXE_CFLAGS) $(DEBUG_FLAGS) $(TEST_SRC)/mapguard_test.c -I $(INCLUDE)  -o $(BUILD_DIR)/mapguard_test -L build/ -ldl
	$(CC) $(CFLAGS) $(EXE_CFLAGS) $(DEBUG_FLAGS) $(TEST_SRC)/mapguard_thread_test.c -I $(INCLUDE)  -o $(BUILD_DIR)/mapguard_thread_test -L build/ -lpthread -ldl

perf_tests:
	$(CC) $(CFLAGS) $(EXE_CFLAGS) -o build/mapguard_perf_test tests/mapguard_perf_test.c

## Build the demo programs (depends on debug library)
demo: library_debug
	@echo "make demo"
	mkdir -p $(BUILD_DIR)/
	$(CC) $(CFLAGS) $(EXE_CFLAGS) $(DEBUG_FLAGS) $(DEMO_SRC)/normal_demo.c -o $(BUILD_DIR)/normal_demo
	$(CC) $(CFLAGS) $(EXE_CFLAGS) $(DEBUG_FLAGS) $(DEMO_SRC)/leak_demo.c -o $(BUILD_DIR)/leak_demo
	$(CC) $(CFLAGS) $(EXE_CFLAGS) $(DEBUG_FLAGS) $(DEMO_SRC)/partial_munmap_demo.c -o $(BUILD_DIR)/partial_munmap_demo
	$(CC) $(CFLAGS) $(EXE_CFLAGS) $(DEBUG_FLAGS) $(DEMO_SRC)/mremap_demo.c -o $(BUILD_DIR)/mremap_demo
	$(CC) $(CFLAGS) $(EXE_CFLAGS) $(DEBUG_FLAGS) $(DEMO_SRC)/growth_demo.c -o $(BUILD_DIR)/growth_demo

## Build everything: library + tests + demos
build_all: clean library_debug tests demo

format:
	clang-format $(INCLUDE)/*.* $(SRC)/*.* $(TEST_SRC)/*.* -i

clean:
	rm -rf build/* test_output.txt core
