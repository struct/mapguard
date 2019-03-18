/* Map Guard test
 * Copyright Chris Rohlf - 2019 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <sys/mman.h>

#define OK 0
#define ERROR -1
#define MG_POISON_BYTE 0xde
#define STATIC_ADDRESS 0x7f3bffaaa000

#if DEBUG
	#define LOG_ERROR(msg, ...)	\
		fprintf(stderr, "[LOG][%d](%s) (%s) - " msg "\n", getpid(), __FUNCTION__, strerror(errno), ##__VA_ARGS__); \
		fflush(stderr);

	#define LOG(msg, ...)	\
		fprintf(stdout, "[LOG][%d](%s) " msg "\n", getpid(), __FUNCTION__, ##__VA_ARGS__); \
		fflush(stdout);
#else
	#define LOG_ERROR(...)
	#define LOG(...)
#endif

#define ALLOC_SIZE 4096

void *map_memory(char *desc, int prot) {
	uint8_t *ptr = mmap(0, ALLOC_SIZE, prot, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);

	if(ptr != MAP_FAILED) {
		LOG("Successfully mmapped %s memory @ %p", desc, ptr);
	} else {
		LOG("Failed to map %s memory", desc);
	}

	return ptr;
}

int32_t unmap_memory(void *ptr) {
	int32_t ret = munmap(ptr, ALLOC_SIZE);

	if(ret == 0) {
		LOG("Successfully munmapped memory @ %p", ptr);
	} else {
		LOG("Failed to munmap memory @ %p", ptr);
	}

	return ret;
}

int32_t unmap_remapped_memory(void *ptr) {
	int32_t ret = munmap(ptr, ALLOC_SIZE*2);

	if(ret == 0) {
		LOG("Successfully munmapped remapped memory @ %p", ptr);
	} else {
		LOG("Failed to munmap remapped memory @ %p", ptr);
	}

	return ret;
}

void *remap_memory(char *desc, void *ptr) {
	void *mptr = mremap(ptr, ALLOC_SIZE, ALLOC_SIZE*2, MREMAP_MAYMOVE);

	if(mptr != MAP_FAILED) {
		LOG("Successfully remapped %s memory %p @ %p", desc, ptr, mptr);
	} else {
		LOG("Failed to remap %s memory", desc);
		abort();
	}

	return mptr;
}

void map_rw_memory() {
	void *ptr = map_memory("RW", PROT_READ|PROT_WRITE);

	if(ptr == MAP_FAILED) {
		LOG("Failed to map RW memory");
		abort();
	} else {
		LOG("Test passed");
	}

	unmap_memory(ptr);
}

void map_rwx_memory() {
	void *ptr = map_memory("RWX", PROT_READ|PROT_WRITE|PROT_EXEC);

	if(ptr != MAP_FAILED) {
		LOG("Successfully mapped RWX memory");
		abort();
	} else {
		LOG("Test passed");
	}
}

void check_x_to_w() {
	void *ptr = map_memory("R-X", PROT_READ|PROT_EXEC);

	if(ptr == MAP_FAILED) {
		LOG("Failed to map R-X memory");
		abort();
	}

	int32_t ret = mprotect(ptr, ALLOC_SIZE, PROT_READ|PROT_WRITE);

	if(ret != ERROR) {
		LOG("Successfully mprotect'd memory R-X to RW-");
		abort();
	} else {
		LOG("Test passed");
	}

	unmap_memory(ptr);
}

void map_rw_then_x_memory() {
	void *ptr = map_memory("RW", PROT_READ|PROT_WRITE);

	if(ptr == MAP_FAILED) {
		LOG("Failed to map RW memory");
		abort();
	}

	int32_t ret = mprotect(ptr, ALLOC_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC);

	if(ret != ERROR) {
		LOG("Successfully mprotect'd memory RWX");
		abort();
	} else {
		LOG("Test passed");
	}

	unmap_memory(ptr);
}

void map_then_mremap() {
	void *ptr = map_memory("RW", PROT_READ|PROT_WRITE);

	if(ptr == MAP_FAILED) {
		LOG("Failed to map RW memory");
		abort();
	}

	ptr = remap_memory("Remap", ptr);

	if(ptr == MAP_FAILED) {
		LOG("Failed to remap memory");
		abort();
	} else {
		LOG("Test passed");
	}

	unmap_remapped_memory(ptr);
}

void map_static_address() {
	uint8_t *ptr = mmap((void *) STATIC_ADDRESS, ALLOC_SIZE, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);

	if(ptr != MAP_FAILED) {
		LOG("Successfully mmapped memory @ %lx", STATIC_ADDRESS);
	} else {
		LOG("Test passed");
	}
}

void check_poison_bytes() {
	void *ptr = map_memory("Poison Bytes", PROT_READ|PROT_WRITE);

	if(ptr == MAP_FAILED) {
		LOG("Failed to map Poison Bytes memory");
		abort();
	}

	uint8_t *byte = &ptr[128];

	if(*byte != MG_POISON_BYTE) {
		LOG("Failed to find poison byte 0x%x, found 0x%x", MG_POISON_BYTE, *byte);
	} else {
		LOG("Test passed")
	}

	unmap_memory(ptr);
}

int main(int argc, char *argv[]) {
	map_rw_memory();
	map_rwx_memory();
	map_rw_then_x_memory();
	map_then_mremap();
	map_static_address();
	check_poison_bytes();
	check_x_to_w();
	return OK;
}