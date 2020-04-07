#include "test_patterns.h"
#include <string.h>

// Pattern of length zero
static const uint8_t PATTERN_EMPTY_INPUT[] = { };
static const uint8_t PATTERN_EMPTY_EXPECTED_OUTPUT[] = {
        0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const struct test842_pattern PATTERN_EMPTY = {
        .uncompressed = PATTERN_EMPTY_INPUT,
        .uncompressed_len = sizeof(PATTERN_EMPTY_INPUT),
        .ref_compressed = PATTERN_EMPTY_EXPECTED_OUTPUT,
        .ref_compressed_len = sizeof(PATTERN_EMPTY_EXPECTED_OUTPUT)
};

// Pattern containing just zeros
static const uint8_t PATTERN_ZEROS_INPUT[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t PATTERN_ZEROS_EXPECTED_OUTPUT[] = {
        0xe6, 0xc2, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const struct test842_pattern PATTERN_ZEROS = {
        .uncompressed = PATTERN_ZEROS_INPUT,
        .uncompressed_len = sizeof(PATTERN_ZEROS_INPUT),
        .ref_compressed = PATTERN_ZEROS_EXPECTED_OUTPUT,
        .ref_compressed_len = sizeof(PATTERN_ZEROS_EXPECTED_OUTPUT)
};

// Pattern containing random data
static const uint8_t PATTERN_RANDOM_INPUT[] = {
        0x0f, 0x07, 0x32, 0xb4, 0xaf, 0x6b, 0xe4, 0x0c,
        0x5f, 0x8b, 0x4e, 0x4c, 0x4e, 0x3f, 0xfd, 0x44,
        0xf0, 0x5f, 0xd6, 0x60, 0x22, 0x4d, 0xc5, 0x2f,
        0x37, 0x8c, 0xbb, 0x3d, 0xd2, 0x17, 0x9b, 0xde
};
static const uint8_t PATTERN_RANDOM_EXPECTED_OUTPUT[] = {
        0x00, 0x78, 0x39, 0x95, 0xa5, 0x7b, 0x5f, 0x20,
        0x60, 0x17, 0xe2, 0xd3, 0x93, 0x13, 0x8f, 0xff,
        0x51, 0x01, 0xe0, 0xbf, 0xac, 0xc0, 0x44, 0x9b,
        0x8a, 0x5e, 0x03, 0x78, 0xcb, 0xb3, 0xdd, 0x21,
        0x79, 0xbd, 0xef, 0x47, 0xe0, 0xe6, 0xe6, 0x00
};
static const struct test842_pattern PATTERN_RANDOM = {
        .uncompressed = PATTERN_RANDOM_INPUT,
        .uncompressed_len = sizeof(PATTERN_RANDOM_INPUT),
        .ref_compressed = PATTERN_RANDOM_EXPECTED_OUTPUT,
        .ref_compressed_len = sizeof(PATTERN_RANDOM_EXPECTED_OUTPUT)
};

// Pattern that compresses to exactly the same size as the input
static const uint8_t PATTERN_LIMIT_INPUT[] = {
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x12, 0x12, 0x12, 0x12, 0x13, 0x13, 0x14, 0x15,
        0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17,
        0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17
};
static const uint8_t PATTERN_LIMIT_EXPECTED_OUTPUT[] = {
        0x00, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
        0x88, 0x04, 0x84, 0x84, 0x84, 0x84, 0xc4, 0xc5,
        0x05, 0x40, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e,
        0x2e, 0x2f, 0xb0, 0x3d, 0x6a, 0xe4, 0xe2, 0x58
};
static const struct test842_pattern PATTERN_LIMIT = {
        .uncompressed = PATTERN_LIMIT_INPUT,
        .uncompressed_len = sizeof(PATTERN_LIMIT_INPUT),
        .ref_compressed = PATTERN_LIMIT_EXPECTED_OUTPUT,
        .ref_compressed_len = sizeof(PATTERN_LIMIT_EXPECTED_OUTPUT)
};

// Pattern that compresses to exactly the same size as the input
static const uint8_t PATTERN_MIXED_INPUT[] = {
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x0f, 0x07, 0x32, 0xb4, 0xaf, 0x6b, 0xe4, 0x0c,
        0x5f, 0x8b, 0x4e, 0x4c, 0x4e, 0x3f, 0xfd, 0x44,
        0xf0, 0x5f, 0xd6, 0x60, 0x22, 0x4d, 0xc5, 0x2f,
        0x37, 0x8c, 0xbb, 0x3d, 0xd2, 0x17, 0x9b, 0xde
};
static const uint8_t PATTERN_MIXED_EXPECTED_OUTPUT[] = {
        0x00, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
        0x8e, 0xc2, 0x00, 0x78, 0x39, 0x95, 0xa5, 0x7b,
        0x5f, 0x20, 0x60, 0x17, 0xe2, 0xd3, 0x93, 0x13,
        0x8f, 0xff, 0x51, 0x01, 0xe0, 0xbf, 0xac, 0xc0,
        0x44, 0x9b, 0x8a, 0x5e, 0x03, 0x78, 0xcb, 0xb3,
        0xdd, 0x21, 0x79, 0xbd, 0xef, 0x27, 0xab, 0x7c,
        0x09, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const struct test842_pattern PATTERN_MIXED = {
        .uncompressed = PATTERN_MIXED_INPUT,
        .uncompressed_len = sizeof(PATTERN_MIXED_INPUT),
        .ref_compressed = PATTERN_MIXED_EXPECTED_OUTPUT,
        .ref_compressed_len = sizeof(PATTERN_MIXED_EXPECTED_OUTPUT)
};

// Pattern that compresses to exactly the same size as the input
static const uint8_t PATTERN_TEXT_INPUT[] = {
        "When my father returned from Milan, he found playing with me in "
        "the hall of our villa a child fairer than pictured cherub—a crea"
        "ture who seemed to shed radiance from her looks and whose form a"
        "nd motions were lighter than the chamois of the hills. The appar"
        "ition was soon explained. With his permission my mother prevaile"
        "d on her rustic guardians to yield their charge to her. They wer"
        "e fond of the sweet orphan. Her presence had seemed a blessing t"
        "o them, but it would be unfair to her to keep her in poverty and"
        " want when Providence afforded her such powerful protection. The"
        "y consulted their village priest, and the result was that Elizab"
        "eth Lavenza became the inmate of my parents’ house—my more than "
        "sister—the beautiful and adored companion of all my occupations "
        "and my pleasures.      "
};
static const uint8_t PATTERN_TEXT_EXPECTED_OUTPUT[] = {
        0x02, 0xbb, 0x43, 0x2b, 0x71, 0x03, 0x6b, 0xc9,
        0x00, 0x19, 0x98, 0x5d, 0x1a, 0x19, 0x5c, 0x88,
        0x1c, 0x80, 0xca, 0xe8, 0xea, 0xe4, 0xdc, 0xca,
        0xc8, 0x40, 0x06, 0x67, 0x26, 0xf6, 0xd2, 0x04,
        0xd6, 0x96, 0xc0, 0x30, 0xb7, 0x16, 0x10, 0x34,
        0x32, 0x90, 0x33, 0x01, 0xbd, 0xd5, 0xb9, 0x90,
        0x81, 0xc1, 0xb1, 0x84, 0x0f, 0x2d, 0x2d, 0xcc,
        0xe4, 0x0e, 0xed, 0x2e, 0x80, 0x68, 0x20, 0x6d,
        0x65, 0x20, 0x69, 0x6e, 0x20, 0x50, 0x2b, 0x29,
        0x03, 0x43, 0x0b, 0x63, 0x60, 0x88, 0x1b, 0xd9,
        0x88, 0x05, 0x1c, 0x88, 0x0a, 0xec, 0xd2, 0x46,
        0xc2, 0x40, 0xc2, 0x40, 0x86, 0x36, 0x80, 0xf0,
        0xb0, 0x43, 0x34, 0xb9, 0x03, 0x10, 0x3a, 0x11,
        0x2c, 0x7d, 0xc1, 0xa5, 0x8d, 0xd0, 0x24, 0x4c,
        0xac, 0x84, 0x0c, 0x62, 0x4e, 0x4e, 0xa2, 0x62,
        0xe2, 0x80, 0x94, 0x2a, 0x63, 0x72, 0x0b, 0x2b,
        0x0b, 0xa3, 0xab, 0x93, 0x28, 0xd0, 0x5a, 0x1b,
        0xc8, 0x1c, 0xd9, 0x59, 0x47, 0x5a, 0x16, 0xe8,
        0xde, 0x8a, 0x24, 0xb0, 0xb7, 0x26, 0x16, 0x46,
        0x91, 0x02, 0xb1, 0xb2, 0x89, 0xb9, 0x37, 0xb6,
        0x90, 0x3c, 0x48, 0x9d, 0xb1, 0xbd, 0xbd, 0xac,
        0xee, 0x64, 0x02, 0x01, 0x6e, 0xed, 0x05, 0x6f,
        0x73, 0x21, 0x66, 0x6f, 0x72, 0x6d, 0x39, 0x03,
        0x08, 0xa8, 0x13, 0x7b, 0xa0, 0xda, 0x5b, 0xdb,
        0x9c, 0xc6, 0x81, 0x94, 0x42, 0xd8, 0xd2, 0xce,
        0xd0, 0xe8, 0xcb, 0x22, 0x70, 0x51, 0x03, 0x28,
        0x89, 0x1c, 0x91, 0x36, 0xb7, 0xa1, 0xa5, 0xcc,
        0x90, 0x94, 0x15, 0x84, 0x2d, 0x0d, 0x24, 0x6e,
        0x65, 0xc7, 0x20, 0x54, 0x12, 0x60, 0x70, 0x70,
        0x43, 0x0b, 0x90, 0xdb, 0x20, 0xf9, 0x5d, 0xd8,
        0x56, 0x1c, 0xdb, 0xdb, 0xdb, 0x84, 0x40, 0xca,
        0xf0, 0xe0, 0x2e, 0xd2, 0xdc, 0xb3, 0x82, 0xe2,
        0x05, 0x76, 0x90, 0x54, 0x10, 0x34, 0x3a, 0x0b,
        0x03, 0x11, 0xb5, 0xa5, 0xcd, 0xcc, 0x82, 0x86,
        0xd7, 0x90, 0x26, 0x31, 0x25, 0x13, 0xb8, 0x39,
        0x32, 0xbb, 0x30, 0xb4, 0xa1, 0xb1, 0x94, 0x2e,
        0x1e, 0x42, 0x80, 0x37, 0x57, 0x37, 0x46, 0x91,
        0xb1, 0x90, 0x33, 0xba, 0xc0, 0x27, 0x44, 0x41,
        0x61, 0x24, 0x81, 0xe4, 0x6d, 0x2c, 0xad, 0x8c,
        0x86, 0x42, 0x51, 0x30, 0x39, 0x22, 0x72, 0x67,
        0x91, 0x0a, 0x4c, 0x80, 0x32, 0xe3, 0x55, 0x1a,
        0x19, 0x5e, 0x46, 0xa4, 0x0c, 0x42, 0xbc, 0x2b,
        0x80, 0x90, 0x40, 0xae, 0x6e, 0xe8, 0xce, 0x84,
        0x0d, 0xee, 0x47, 0x70, 0x68, 0x10, 0x8d, 0x48,
        0x65, 0xa9, 0x39, 0x95, 0xcc, 0x06, 0x0a, 0x12,
        0x0c, 0x2c, 0x88, 0xb7, 0x11, 0x85, 0x95, 0x19,
        0x89, 0xb3, 0x49, 0xcd, 0xa4, 0x65, 0x86, 0x4d,
        0xe4, 0x00, 0xac, 0xad, 0xad, 0x11, 0x62, 0x75,
        0xca, 0x1b, 0x88, 0xd0, 0xa5, 0x89, 0x03, 0x13,
        0x48, 0x5d, 0x5b, 0x81, 0x0c, 0x30, 0x70, 0x15,
        0x31, 0x24, 0x81, 0xad, 0x19, 0xc0, 0x82, 0xe2,
        0xa8, 0xb1, 0x63, 0x37, 0xbb, 0x03, 0x3a, 0x3c,
        0xb0, 0x48, 0x54, 0x68, 0x43, 0x2a, 0x0b, 0x7a,
        0x64, 0x0a, 0x0a, 0x4b, 0x28, 0x64, 0x65, 0x6e,
        0x63, 0x21, 0x33, 0x0b, 0x32, 0xf3, 0x93, 0x21,
        0xc5, 0x8b, 0xa8, 0xae, 0xac, 0x6a, 0x1c, 0x70,
        0x6f, 0x77, 0x65, 0x72, 0x66, 0x43, 0xab, 0x64,
        0x92, 0x93, 0x5c, 0x0d, 0x99, 0x1b, 0x8b, 0x9f,
        0x16, 0x74, 0xf2, 0x40, 0xc6, 0xde, 0xcb, 0x21,
        0x86, 0xb2, 0xe6, 0xd4, 0xb2, 0xb4, 0xaa, 0x85,
        0x10, 0xc2, 0xce, 0xbb, 0x3b, 0x60, 0x87, 0x37,
        0x4e, 0x44, 0xf4, 0x8b, 0x04, 0x10, 0x9c, 0xdd,
        0x4c, 0xd8, 0xe8, 0x86, 0xc2, 0xe6, 0xde, 0xf7,
        0x2c, 0xa4, 0x56, 0xc6, 0x97, 0xa1, 0x30, 0xb1,
        0x32, 0xba, 0x0a, 0x26, 0x30, 0x89, 0xd9, 0x95,
        0xb9, 0xeb, 0x6d, 0x89, 0x95, 0x2c, 0x6c, 0x3b,
        0x25, 0x90, 0x90, 0x34, 0xb7, 0x36, 0xb0, 0xba,
        0x2e, 0x9d, 0xbd, 0x99, 0x88, 0x85, 0xc1, 0x85,
        0x46, 0xcd, 0xce, 0x8e, 0x7c, 0x50, 0x13, 0x2f,
        0x90, 0xe9, 0x73, 0x65, 0xe2, 0x80, 0x44, 0xa3,
        0x69, 0x0b, 0x99, 0xb5, 0xc3, 0x30, 0x7b, 0xd1,
        0x30, 0x67, 0x5b, 0x94, 0x74, 0x7b, 0x87, 0x5b,
        0x2b, 0x0b, 0xab, 0xa2, 0x5a, 0x59, 0x86, 0x06,
        0x0d, 0x7e, 0x64, 0x6f, 0x36, 0xa1, 0x69, 0x13,
        0x6b, 0x85, 0x64, 0x14, 0xa0, 0xd4, 0x1f, 0x9e,
        0xa8, 0x01, 0x6f, 0x63, 0x63, 0x75, 0x92, 0x9d,
        0x3c, 0x3c, 0x2d, 0xd3, 0x33, 0x12, 0x50, 0xa0,
        0x3a, 0x75, 0x72, 0xd2, 0x54, 0x69, 0x01, 0x01,
        0x01, 0x01, 0x00, 0x07, 0x8b, 0x30, 0x2e, 0x1a,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const struct test842_pattern PATTERN_TEXT = {
        .uncompressed = PATTERN_TEXT_INPUT,
        .uncompressed_len = sizeof(PATTERN_TEXT_INPUT),
        .ref_compressed = PATTERN_TEXT_EXPECTED_OUTPUT,
        .ref_compressed_len = sizeof(PATTERN_TEXT_EXPECTED_OUTPUT)
};

const struct test842_pattern *test842_get_pattern_by_name(const char *name) {
    if (strcmp(name, "empty") == 0) {
        return &PATTERN_EMPTY;
    } else if (strcmp(name, "zeros") == 0) {
        return &PATTERN_ZEROS;
    } else if (strcmp(name, "random") == 0) {
        return &PATTERN_RANDOM;
    } else if (strcmp(name, "mixed") == 0) {
        return &PATTERN_MIXED;
    } else if (strcmp(name, "limit") == 0) {
        return &PATTERN_LIMIT;
    } else if (strcmp(name, "text") == 0) {
        return &PATTERN_TEXT;
    } else {
        return NULL;
    }
}
