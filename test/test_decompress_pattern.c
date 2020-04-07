// Tests that the result of decompressing some data matches the expected reference output
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdalign.h>
#include "test_patterns.h"
#include "test_util.h"

int main(int argc, char *argv[]) {
    const struct test842_impl *impl;
    const struct test842_pattern *pattern;
    if (argc != 3 ||
        (impl = test842_get_impl_by_name(argv[1])) == NULL ||
        (pattern = test842_get_pattern_by_name(argv[2])) == NULL) {
        printf("test_decompress_pattern IMPL PATTERN\n");
        return EXIT_FAILURE;
    }

    alignas(8) uint8_t in[pattern->ref_compressed_len], out[pattern->uncompressed_len];
    memcpy(in, pattern->ref_compressed, pattern->ref_compressed_len);
    size_t olen = pattern->uncompressed_len;
    if (impl->decompress(in, pattern->ref_compressed_len, out, &olen) != 0) {
        printf("Decompression failed\n");
        return EXIT_FAILURE;
    }

    if (olen != pattern->uncompressed_len ||
        memcmp(out, pattern->uncompressed, pattern->uncompressed_len) != 0) {
        printf("Invalid decompression result\n");
        printf("Input (%zu bytes):\n", pattern->ref_compressed);
        test842_hexdump(pattern->ref_compressed, pattern->ref_compressed_len);
        printf("Expected output (%zu bytes):\n", pattern->uncompressed);
        test842_hexdump(pattern->uncompressed, pattern->uncompressed_len);
        printf("Actual output (%zu bytes):\n", olen);
        test842_hexdump(out, olen);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
