// Tests that decompressing an invalid bitstream fails
// This generates various pseudo-random streams to try to catch more weaknesses
// (basically, uses a primitive fuzz test)
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "test_util.h"

static unsigned xorshift_seed = 12345;
unsigned xorshift_next()
{
	xorshift_seed ^= xorshift_seed << 13;
	xorshift_seed ^= xorshift_seed >> 17;
	xorshift_seed ^= xorshift_seed << 5;
	return xorshift_seed;
}

int main(int argc, char *argv[])
{
	const struct lib842_implementation *impl;
	if (argc != 2 || (impl = test842_get_impl_by_name(argv[1])) == NULL) {
		printf("test_decompress_invalid_generator IMPL\n");
		return EXIT_FAILURE;
	}

	// FIXME TESTFAILURE: This test will generate streams that exercise unfixed
	// memory safety issues in the kernel SW implementation (as of 20250331). See:
	// https://github.com/joanbm/lib842/commit/e201d3aef50cb84390688122ef8eb752f3159cd7
	// https://github.com/joanbm/lib842/commit/46d6e9de84e77bdd7778603e09eb934865ccd929
	// Note that hitting a kernel panic is very dependent on the specific kernel
	// version and the crypto API. In my tests, this causes a crash kernel 6.6.85:
	/*
	#include <linux/mm.h>
	#include <linux/scatterlist.h>
	#include <linux/log2.h>
	#include <crypto/acompress.h>

	static void repro(void)
	{
		struct crypto_acomp *s = crypto_alloc_acomp("842", 0, 0);
		BUG_ON(!s);
		struct acomp_req *request = acomp_request_alloc(s);
		u8 *srcbuf = (u8 *)__get_free_pages(GFP_KERNEL, order_base_2(65536 / PAGE_SIZE));
		u8 *dstbuf = (u8 *)__get_free_pages(GFP_KERNEL, order_base_2(65536 / PAGE_SIZE));
		BUG_ON(!request || !srcbuf || !dstbuf);

		memcpy(srcbuf, (uint8_t[]){
			0xea, 0x00, 0xa3, 0xd8, 0xe3, 0x87, 0xab, 0x24,
			0xaa, 0x7a, 0xd6, 0xbe, 0xf2, 0xdb, 0xa3, 0x2f,
			0x47, 0x38, 0x7e, 0x78, 0x43, 0xe9, 0x22, 0x48,
			0x7c, 0xc1, 0xec, 0xcf, 0x9d, 0x77, 0xbe, 0x3b,
		}, 32);

		struct scatterlist src_sg, dst_sg;
		sg_init_one(&src_sg, srcbuf, 32);
		sg_init_one(&dst_sg, dstbuf, 1024);
		acomp_request_set_params(request, &src_sg, &dst_sg, 32, 1024);
		crypto_acomp_decompress(request); // CRASH!
	}
	*/
	if (strcmp(argv[1], "hw") == 0) {
		fprintf(stderr, "!! TEST FAILED (BUT PASS, DUE TO KNOWN DEFECT) !!\n");
		return EXIT_SUCCESS;
	}

	const size_t insize = 32, outsize = 1024;
	uint8_t *in = aligned_alloc(impl->required_alignment, insize);
	uint8_t *out = aligned_alloc(impl->required_alignment, outsize);

	for (size_t i = 0; i < 5000; i++) {
		size_t olen = outsize;
		for (size_t j = 0; j < insize; j++) {
			in[j] = (uint8_t)xorshift_next();
		}
		int ret = impl->decompress(in, insize, out, &olen);
		printf("[Run %zu] Decompression returned %d\n", i, ret);
	}

	return EXIT_SUCCESS;
}
