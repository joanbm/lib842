
#ifndef __842_INTERNAL_H__
#define __842_INTERNAL_H__

/* The 842 compressed format is made up of multiple blocks, each of
 * which have the format:
 *
 * <template>[arg1][arg2][arg3][arg4]
 *
 * where there are between 0 and 4 template args, depending on the specific
 * template operation.  For normal operations, each arg is either a specific
 * number of data bytes to add to the output buffer, or an index pointing
 * to a previously-written number of data bytes to copy to the output buffer.
 *
 * The template code is a 5-bit value.  This code indicates what to do with
 * the following data.  Template codes from 0 to 0x19 should use the template
 * table, the static "decomp_ops" table used in decompress.  For each template
 * (table row), there are between 1 and 4 actions; each action corresponds to
 * an arg following the template code bits.  Each action is either a "data"
 * type action, or a "index" type action, and each action results in 2, 4, or 8
 * bytes being written to the output buffer.  Each template (i.e. all actions
 * in the table row) will add up to 8 bytes being written to the output buffer.
 * Any row with less than 4 actions is padded with noop actions, indicated by
 * N0 (for which there is no corresponding arg in the compressed data buffer).
 *
 * "Data" actions, indicated in the table by D2, D4, and D8, mean that the
 * corresponding arg is 2, 4, or 8 bytes, respectively, in the compressed data
 * buffer should be copied directly to the output buffer.
 *
 * "Index" actions, indicated in the table by I2, I4, and I8, mean the
 * corresponding arg is an index parameter that points to, respectively, a 2,
 * 4, or 8 byte value already in the output buffer, that should be copied to
 * the end of the output buffer.  Essentially, the index points to a position
 * in a ring buffer that contains the last N bytes of output buffer data.
 * The number of bits for each index's arg are: 8 bits for I2, 9 bits for I4,
 * and 8 bits for I8.  Since each index points to a 2, 4, or 8 byte section,
 * this means that I2 can reference 512 bytes ((2^8 bits = 256) * 2 bytes), I4
 * can reference 2048 bytes ((2^9 = 512) * 4 bytes), and I8 can reference 2048
 * bytes ((2^8 = 256) * 8 bytes).  Think of it as a kind-of ring buffer for
 * each of I2, I4, and I8 that are updated for each byte written to the output
 * buffer.  In this implementation, the output buffer is directly used for each
 * index; there is no additional memory required.  Note that the index is into
 * a ring buffer, not a sliding window; for example, if there have been 260
 * bytes written to the output buffer, an I2 index of 0 would index to byte 256
 * in the output buffer, while an I2 index of 16 would index to byte 16 in the
 * output buffer.
 *
 * There are also 3 special template codes; 0x1b for "repeat", 0x1c for
 * "zeros", and 0x1e for "end".  The "repeat" operation is followed by a 6 bit
 * arg N indicating how many times to repeat.  The last 8 bytes written to the
 * output buffer are written again to the output buffer, N + 1 times.  The
 * "zeros" operation, which has no arg bits, writes 8 zeros to the output
 * buffer.  The "end" operation, which also has no arg bits, signals the end
 * of the compressed data.  There may be some number of padding (don't care,
 * but usually 0) bits after the "end" operation bits, to fill the buffer
 * length to a specific byte multiple (usually a multiple of 8, 16, or 32
 * bytes).
 *
 * This software implementation also uses one of the undefined template values,
 * 0x1d as a special "short data" template code, to represent less than 8 bytes
 * of uncompressed data.  It is followed by a 3 bit arg N indicating how many
 * data bytes will follow, and then N bytes of data, which should be copied to
 * the output buffer.  This allows the software 842 compressor to accept input
 * buffers that are not an exact multiple of 8 bytes long.  However, those
 * compressed buffers containing this sw-only template will be rejected by
 * the 842 hardware decompressor, and must be decompressed with this software
 * library.  The 842 software compression module includes a parameter to
 * disable using this sw-only "short data" template, and instead simply
 * reject any input buffer that is not a multiple of 8 bytes long.
 *
 * After all actions for each operation code are processed, another template
 * code is in the next 5 bits.  The decompression ends once the "end" template
 * code is detected.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include <errno.h>
#include <string.h>


#include "../../include/sw842.h"

#include "../common/memaccess.h"
#include "../common/endianness.h"
#include "../common/crc32.h"
#include "kerneldeps.h"
#include "../common/hash.hpp"

//#define DEBUG 1

/* special templates */
#define OP_REPEAT	(0x1B)
#define OP_ZEROS	(0x1C)
#define OP_END		(0x1E)

/* additional bits of each op param */
#define OP_BITS		(5)
#define REPEAT_BITS	(6)
#define I2_BITS		(8)
#define I4_BITS		(9)
#define I8_BITS		(8)
#define D2_BITS 	(16)
#define D4_BITS 	(32)
#define D8_BITS 	(64)
#define CRC_BITS	(32)

#define REPEAT_BITS_MAX		(0x3f)

/* Arbitrary values used to indicate action */
#define OP_ACTION	(0x70)
#define OP_ACTION_INDEX	(0x10)
#define OP_ACTION_DATA	(0x20)
#define OP_ACTION_NOOP	(0x40)
#define OP_AMOUNT	(0x0f)
#define OP_AMOUNT_0	(0x00)
#define OP_AMOUNT_2	(0x02)
#define OP_AMOUNT_4	(0x04)
#define OP_AMOUNT_8	(0x08)

#define D2		(OP_ACTION_DATA  | OP_AMOUNT_2)
#define D4		(OP_ACTION_DATA  | OP_AMOUNT_4)
#define D8		(OP_ACTION_DATA  | OP_AMOUNT_8)
#define I2		(OP_ACTION_INDEX | OP_AMOUNT_2)
#define I4		(OP_ACTION_INDEX | OP_AMOUNT_4)
#define I8		(OP_ACTION_INDEX | OP_AMOUNT_8)
#define N0		(OP_ACTION_NOOP  | OP_AMOUNT_0)

#define I2N (13)
#define I4N (53)
#define I8N (149)

/* the max of the regular templates - not including the special templates */
#define OPS_MAX		(0x1a)

struct sw842_param {
	struct bitstream* stream;

	uint8_t *in;
	uint8_t *instart;
	uint64_t ilen;
	uint8_t *out;
	uint64_t olen;

	uint64_t data[7];
	uint64_t hashes[7];
	uint16_t validity[7];
	uint16_t templateKeys[7];

	int index8[1];
	int index4[2];
	int index2[4];
	uint64_t hash8[1];
	uint64_t hash4[2];
	uint16_t hash2[4];

	int16_t hashTable16[1 << DICT16_BITS]; // 1024 * 2 bytes =   2 KiB
	int16_t hashTable32[1 << DICT32_BITS]; // 2048 * 2 bytes =   4 KiB
	int16_t hashTable64[1 << DICT64_BITS]; // 1024 * 2 bytes =   2 KiB
	uint16_t ringBuffer16[1 << I2_BITS];   // 256  * 2 bytes = 0.5 KiB
	uint32_t ringBuffer32[1 << I4_BITS];   // 512  * 4 bytes =   2 KiB
	uint64_t ringBuffer64[1 << I8_BITS];   // 256  * 8 bytes =   2 KiB


};

struct sw842_param_decomp {
	uint8_t *in;
	uint8_t bit;
	uint64_t ilen;
	uint8_t *out;
	uint8_t *ostart;
	uint64_t olen;
};

uint64_t static inline bytes_rounded_up(uint64_t bits) {
	return (bits + 8 - 1) / 8;
}

struct bitstream* stream_open(void* buffer, size_t bytes);
void stream_close(struct bitstream* s);
size_t stream_size(const struct bitstream* s);
//uint64_t stream_read_bits(struct bitstream* s, uint8_t n);
void stream_write_bits(struct bitstream* s, uint64_t value, uint8_t n);
size_t stream_flush(struct bitstream* s);

#endif
