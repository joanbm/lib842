#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/time.h>

#if defined(USEAIX)
#include <sys/types.h>
#include <sys/vminfo.h>
#define ALIGNMENT 4096
#define lib842_decompress(in, ilen, out, olen) accel_decompress(in, ilen, out, olen, 0)
#define lib842_compress(in, ilen, out, olen) accel_compress(in, ilen, out, olen, 0)
#elif defined(USEHW)
#include "hw842.h"
#define lib842_decompress hw842_decompress
#define lib842_compress hw842_compress
#elif defined(USEOPTSW)
#include "sw842.h"
#define lib842_decompress optsw842_decompress
#define lib842_compress optsw842_compress
#else
#include "sw842.h"
#define lib842_decompress sw842_decompress
#define lib842_compress sw842_compress
#endif

//#define CHUNK_SIZE ((size_t)32768)
//#define CHUNK_SIZE ((size_t)1024)
#define CHUNK_SIZE ((size_t)4096)

//#define CONDENSE

static void *alloc_chunk(size_t size)
{
#ifdef ALIGNMENT
	size_t padded_size = (size + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1);
	return aligned_alloc(ALIGNMENT, padded_size);
#else
	return malloc(size);
#endif
}

long long timestamp()
{
	struct timeval te;
	gettimeofday(&te, NULL);
	long long ms = te.tv_sec * 1000LL + te.tv_usec / 1000;
	return ms;
}

size_t nextMultipleOfChunkSize(size_t input)
{
	return (input + (CHUNK_SIZE - 1)) & ~(CHUNK_SIZE - 1);
}

static uint8_t *read_file(const char *file_name, size_t *ilen)
{
	FILE *fp = fopen(file_name, "rb");
	if (fp == NULL) {
		fprintf(stderr, "FAIL: Could not open the file at path '%s'.\n",
			file_name);
		return NULL;
	}

	if (fseek(fp, 0, SEEK_END) != 0) {
		fprintf(stderr, "FAIL: Could not seek the file to the end.\n");
		goto fail_file;
	}

	long flen = ftell(fp);
	if (flen == -1) {
		fprintf(stderr, "FAIL: Could not get the file length.\n");
		goto fail_file;
	}

	if (fseek(fp, 0, SEEK_SET) != 0) {
		fprintf(stderr, "FAIL: Could not seek the file to the start.\n");
		goto fail_file;
	}

	*ilen = nextMultipleOfChunkSize((size_t)flen);

	uint8_t *file_data = alloc_chunk(*ilen);
	if (file_data == NULL) {
		fprintf(stderr, "FAIL: Could not allocate memory to read the file.\n");
		goto fail_file;
	}

	memset(file_data, 0, *ilen);
	if (fread(file_data, 1, (size_t)flen, fp) != (size_t)flen) {
		fprintf(stderr,
			"FAIL: Reading file content to memory failed.\n");
		goto fail_file_data_and_file;
	}
	fclose(fp);

	printf("original file length: %li\n", flen);
	printf("original file length (padded): %zu\n", *ilen);
	return file_data;

fail_file_data_and_file:
	free(file_data);
fail_file:
	fclose(fp);
	return NULL;
}

static uint8_t *get_test_string(size_t *ilen) {
	static const uint8_t TEST_STRING[] = {
		0x30, 0x30, 0x31, 0x31, 0x32, 0x32, 0x33, 0x33,
		0x34, 0x34, 0x35, 0x35, 0x36, 0x36, 0x37, 0x37,
		0x38, 0x38, 0x39, 0x39, 0x40, 0x40, 0x41, 0x41,
		0x42, 0x42, 0x43, 0x43, 0x44, 0x44, 0x45, 0x45
	}; //"0011223344556677889900AABBCCDDEE";

	*ilen = sizeof(TEST_STRING);
	uint8_t *test_string = alloc_chunk(*ilen);
	if (test_string == NULL) {
		fprintf(stderr, "FAIL: Could not allocate memory for the test string.\n");
		return NULL;
	}

	memcpy(test_string, TEST_STRING, sizeof(TEST_STRING));
	return test_string;
}

static bool compress_benchmark_core(const uint8_t *in, size_t ilen,
				    uint8_t *out, size_t *olen,
				    uint8_t *decompressed, size_t *dlen,
				    long long *time_comp,
#ifdef CONDENSE
				    long long *time_condense,
#endif
				    long long *time_decomp) {
	bool ret = false;
	bool omp_success = true;

	size_t num_chunks = ilen / CHUNK_SIZE;
#ifdef CONDENSE
	size_t *compressedChunkPositions = malloc(sizeof(size_t) * num_chunks);
	if (compressedChunkPositions == NULL) {
		fprintf(stderr, "FAIL: Could not allocate memory for the compressed chunk positions.\n");
		return ret;
	}
#endif
	size_t *compressedChunkSizes = malloc(sizeof(size_t) * num_chunks);
	if (compressedChunkSizes == NULL) {
		fprintf(stderr, "FAIL: Could not allocate memory for the compressed chunk sizes.\n");
		goto free_3;
	}
	size_t *decompressedChunkSizes = malloc(sizeof(size_t) * num_chunks);
	if (decompressedChunkSizes == NULL) {
		fprintf(stderr, "FAIL: Could not allocate memory for the decompressed chunk sizes.\n");
		goto free_2;
	}

	long long timestart_comp = timestamp();
#pragma omp parallel for
	for (size_t chunk_num = 0; chunk_num < num_chunks; chunk_num++) {
		size_t chunk_olen = CHUNK_SIZE * 2;
		const uint8_t *chunk_in = in + (CHUNK_SIZE * chunk_num);
		uint8_t *chunk_out =
			out + ((CHUNK_SIZE * 2) * chunk_num);

		int err = lib842_compress(chunk_in, CHUNK_SIZE, chunk_out,
				&chunk_olen);
		if (err < 0) {
			bool is_first_failure;
			#pragma omp atomic capture
			{ is_first_failure = omp_success; omp_success = false; }
			if (is_first_failure) {
				fprintf(stderr, "FAIL: Error during compression (%d): %s\n",
				        -err, strerror(-err));
			}
		}
		compressedChunkSizes[chunk_num] = chunk_olen;
	}
	*time_comp = timestamp() - timestart_comp;

	if (!omp_success)
		goto free_x;

#ifdef CONDENSE
	long long timestart_condense = timestamp();
#endif

	*olen = 0;

	for (size_t chunk_num = 0; chunk_num < num_chunks; chunk_num++) {
#ifdef CONDENSE
		compressedChunkPositions[chunk_num] = *olen;
#endif
		*olen += compressedChunkSizes[chunk_num];
	}

#ifdef CONDENSE
	uint8_t *out_condensed = malloc(*olen);

#pragma omp parallel for
	for (size_t chunk_num = 0; chunk_num < num_chunks; chunk_num++) {
		uint8_t *chunk_out =
			out + ((CHUNK_SIZE * 2) * chunk_num);
		uint8_t *chunk_condensed =
			out_condensed +
			compressedChunkPositions[chunk_num];
		memcpy(chunk_condensed, chunk_out,
		       compressedChunkSizes[chunk_num]);
	}
	*time_condense = timestamp() - timestart_condense;
#endif

	long long timestart_decomp = timestamp();
#pragma omp parallel for
	for (size_t chunk_num = 0; chunk_num < num_chunks; chunk_num++) {
		size_t chunk_dlen = CHUNK_SIZE;
#ifdef CONDENSE
		uint8_t *chunk_out = out_condensed + compressedChunkPositions[chunk_num];
#else
		uint8_t *chunk_out = out + ((CHUNK_SIZE * 2) * chunk_num);
#endif
		uint8_t *chunk_decomp =
			decompressed + (CHUNK_SIZE * chunk_num);
		int err = lib842_decompress(chunk_out,
				  compressedChunkSizes[chunk_num],
				  chunk_decomp, &chunk_dlen);
		if (err < 0) {
			bool is_first_failure;
			#pragma omp atomic capture
			{ is_first_failure = omp_success; omp_success = false; }
			if (is_first_failure) {
				fprintf(stderr, "FAIL: Error during decompression (%d): %s\n",
				        -err, strerror(-err));
			}
		}
		decompressedChunkSizes[chunk_num] = chunk_dlen;
	}
	*time_decomp = timestamp() - timestart_decomp;

	if (!omp_success)
		goto free_1;

	*dlen = 0;
	for (size_t chunk_num = 0; chunk_num < num_chunks; chunk_num++)
		*dlen += decompressedChunkSizes[chunk_num];

	if (ilen != *dlen || memcmp(in, decompressed, ilen) != 0) {
		fprintf(stderr,
			"FAIL: Decompressed data differs from the original input data.\n");
		goto free_1;
	}

	ret = true;

free_1:
#ifdef CONDENSE
	free(out_condensed);
#endif
free_x:
	free(decompressedChunkSizes);
free_2:
	free(compressedChunkSizes);
free_3:
#ifdef CONDENSE
	free(compressedChunkPositions);
#endif

	return ret;
}

static bool compress_benchmark(const uint8_t *in, size_t ilen,
			       uint8_t *out, size_t olen,
			       uint8_t *decompressed, size_t dlen) {
	printf("Using chunks of %zu bytes\n", CHUNK_SIZE);

	long long time_comp, time_decomp;
#ifdef CONDENSE
	long long time_condense;
#endif
	if (!compress_benchmark_core(in, ilen, out, &olen, decompressed, &dlen,
				     &time_comp,
#ifdef CONDENSE
				     &time_condense,
#endif
				     &time_decomp))
		return false;

	printf("Input: %zu bytes\n", ilen);
	printf("Output: %zu bytes\n", olen);
	printf("Compression factor: %f\n",
	       (float)olen / (float)ilen);
	printf("Compression performance: %lld ms / %f MiB/s\n",
	       time_comp, (ilen / 1024 / 1024) / ((float)time_comp / 1000));
#ifdef CONDENSE
	printf("Condensation performance: %lld ms / %f MiB/s\n",
	       time_condense, (olen / 1024 / 1024) / ((float)time_condense / 1000));
#endif
	printf("Decompression performance: %lld ms / %f MiB/s\n",
	       time_decomp, (dlen / 1024 / 1024) / ((float)time_decomp / 1000));

	printf("Compression- and decompression was successful!\n");
	return true;
}

static bool simple_test_core(const uint8_t *in, size_t ilen,
			     uint8_t *out, size_t *olen,
			     uint8_t *decompressed, size_t *dlen)
{
	int err;

	err = lib842_compress(in, ilen, out, olen);
	if (err < 0) {
		fprintf(stderr, "Error during compression (%d): %s\n",
		        -err, strerror(-err));
		return false;
	}

	err = lib842_decompress(out, *olen, decompressed, dlen);
	if (err < 0) {
		fprintf(stderr, "Error during decompression (%d): %s\n",
		        -err, strerror(-err));
		return false;
	}

	return true;
}

static bool simple_test(const uint8_t *in, size_t ilen,
			uint8_t *out, size_t olen,
			uint8_t *decompressed, size_t dlen)
{
	if (!simple_test_core(in, ilen, out, &olen, decompressed, &dlen))
		return false;

	printf("Input: %zu bytes\n", ilen);
	printf("Output: %zu bytes\n", olen);
	printf("Compression factor: %f\n", (float)olen / (float)ilen);

	for (size_t i = 0; i < olen; i++) {
		printf("%02x:", out[i]);
	}

	printf("\n\n");

	for (size_t i = 0; i < dlen; i++) {
		printf("%02x:", decompressed[i]);
	}

	printf("\n\n");

	if (ilen != dlen || memcmp(in, decompressed, ilen) != 0) {
		fprintf(stderr,
			"FAIL: Decompressed data differs from the original input data.\n");
		return false;
	}

	printf("Compression- and decompression was successful!\n");
	return true;
}

int main(int argc, const char *argv[])
{
	int ret = EXIT_FAILURE;

	size_t ilen;
	uint8_t *in = (argc <= 1) ? get_test_string(&ilen)
				  : read_file(argv[1], &ilen);
	if (in == NULL)
		return ret;

	size_t olen = ilen * 2;
	uint8_t *out = alloc_chunk(olen);
	if (out == NULL) {
		fprintf(stderr, "FAIL: out = alloc_chunk(...) failed!\n");
		goto return_free_in;
	}
	memset(out, 0, olen);

#ifdef USEHW
	size_t dlen = ilen * 2;
#else
	size_t dlen = ilen;
#endif
	uint8_t *decompressed = alloc_chunk(dlen);
	if (decompressed == NULL) {
		fprintf(stderr, "FAIL: decompressed = alloc_chunk(...) failed!\n");
		goto return_free_out;
	}
	memset(decompressed, 0, dlen);

	if (ilen > CHUNK_SIZE) {
		if (!compress_benchmark(in, ilen, out, olen, decompressed, dlen))
			goto return_free_decompressed;
	} else {
		if (!simple_test(in, ilen, out, olen, decompressed, dlen))
			goto return_free_decompressed;
	}

	ret = EXIT_SUCCESS;

return_free_decompressed:
	free(decompressed);
return_free_out:
	free(out);
return_free_in:
	free(in);
	return ret;
}
