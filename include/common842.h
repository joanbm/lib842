#ifndef __COMMON842_H__
#define __COMMON842_H__

#include <stdint.h>
#include <stddef.h>

// ----------------------------------------
// Common interface for all implementations
// ----------------------------------------

// Compresses a sequence of bytes in single chunk mode
// in: Input buffer containing the data to be compressed
// ilen: Size of the input data, in bytes
// out: Output buffer where the uncompressed data will be written
// olen: When called, contains the available size of the output buffer, in bytes
//       On return, contains the size used for compression of the output buffer, in bytes
// Returns: 0 on success, a negative value (errno) on failure
typedef int (*lib842_compress_func)(const uint8_t *in, size_t ilen,
				    uint8_t *out, size_t *olen);

// Decompresses a sequence of bytes in single chunk mode
// in: Input buffer containing the compressed data
// ilen: Size of the input data, in bytes
// out: Output buffer where the original uncompressed data will be written
// olen: When called, contains the available size of the output buffer, in bytes
//       On return, contains the size of the original data, in bytes
// Returns: 0 on success, a negative value (errno) on failure
typedef int (*lib842_decompress_func)(const uint8_t *in, size_t ilen,
				      uint8_t *out, size_t *olen);


static const uint8_t LIB842_COMPRESSED_CHUNK_MARKER[16] = {
	0xbe, 0x5a, 0x46, 0xbf, 0x97, 0xe5, 0x2d, 0xd7, 0xb2, 0x7c, 0x94, 0x1a, 0xee, 0xd6, 0x70, 0x76
};

#endif
