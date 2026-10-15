/* Counts memcpy/memmove calls and bytes for the whole process; printed at exit.
 * Preloaded only for measurement: real copies are still performed by the real functions. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
static uint64_t calls, bytes, hist[64];
static void *(*real_memcpy)(void *, const void *, size_t);
static void *(*real_memmove)(void *, const void *, size_t);
__attribute__((constructor)) static void init(void) {
    real_memcpy = dlsym(RTLD_NEXT, "memcpy");
    real_memmove = dlsym(RTLD_NEXT, "memmove");
}
static void record(size_t n) {
    calls++;
    bytes += n;
    int b = 0;
    for (size_t x = n; x > 1; x >>= 1) b++;
    hist[b]++;
}
void *memcpy(void *d, const void *s, size_t n) { record(n); return real_memcpy(d, s, n); }
void *memmove(void *d, const void *s, size_t n) { record(n); return real_memmove(d, s, n); }
__attribute__((destructor)) static void report(void) {
    fprintf(stderr, "copy_calls,%llu\ncopy_bytes,%llu\n", (unsigned long long)calls, (unsigned long long)bytes);
    for (int b = 0; b < 64; b++)
        if (hist[b]) fprintf(stderr, "hist_log2,%d,%llu\n", b, (unsigned long long)hist[b]);
}
