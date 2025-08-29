/**********************************************************************
  Copyright(c) 2025 Intel Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#if !defined(_WIN32) && !defined(_WIN64)
#include <strings.h>
#endif
#include <aes_cbc.h>
#include <aes_gcm.h>
#include <aes_xts.h>
#include <aes_keyexp.h>
#include <test.h>
#include <openssl/evp.h>
#include "ossl_helper.h"
#include "gcm_vectors.h"

// Windows compatibility for case-insensitive string comparison
#if defined(_WIN32) || defined(_WIN64)
#define strcasecmp  _stricmp
#define strncasecmp _strnicmp
#endif

#define DEFAULT_TEST_LEN   8 * 1024
#define DEFAULT_AAD_LEN    20
#define MAX_AAD_LEN        256
#define TEST_LARGE_MEM_LEN (1024ULL * 1024 * 1024)

// Cached test, loop many times over small dataset
#define CBC_TEST_LOOPS 400000
#define GCM_TEST_LOOPS 400000
#define XTS_TEST_LOOPS 3000000

#ifndef TEST_SEED
#define TEST_SEED 0x1234
#endif

// Global flag to control OpenSSL benchmarks
static int enable_openssl = 0;

// Operation mode enumeration
typedef enum { OP_ENCRYPT = 0, OP_DECRYPT = 1 } operation_mode_t;

// Global operation mode (encrypt by default)
static operation_mode_t operation_mode = OP_ENCRYPT;

// Global CSV output mode
static int csv_output = 0;

// Global in-place operation mode
static int in_place = 0;

// Global iteration counts (0 means use defaults)
static int custom_iterations = 0;

// Global buffer alignment (64 bytes by default)
static size_t buffer_alignment = 64;

// Global AAD length for GCM operations
static int aad_length = DEFAULT_AAD_LEN;

// Size range configuration
typedef struct {
        size_t start_size;
        size_t end_size;
        size_t step_size;
        int use_range;
} size_range_t;

// Global size range (single size by default)
static size_range_t size_range = { DEFAULT_TEST_LEN, DEFAULT_TEST_LEN, 0, 0 };

// Global buffers
static unsigned char *plaintext = NULL;
static unsigned char *ciphertext = NULL;

// Keys and IVs - allocate maximum size (32 bytes) for all keys
static uint8_t test_key_128[32];
static uint8_t test_key_192[32];
static uint8_t test_key_256[32];
static uint8_t test_iv[16];

int cold_test = 0;

// Helper function to parse size values with optional K (KB) or M (MB) suffix
static size_t
parse_size_value(const char *const size_str)
{
        size_t size_val;
        char *endptr;
        size_t multiplier = 1;
        char *const str_copy = strdup(size_str);

        // Check if strdup failed
        if (!str_copy)
                return 0;

        // Check for size suffixes (K for KB, M for MB)
        const int len = strlen(str_copy);
        if (len > 0) {
                // Convert to uppercase for case-insensitive comparison
                char last_char = toupper(str_copy[len - 1]);

                if (last_char == 'K') {
                        multiplier = 1024;
                        str_copy[len - 1] = '\0'; // Remove the suffix
                } else if (last_char == 'M') {
                        multiplier = 1024 * 1024;
                        str_copy[len - 1] = '\0'; // Remove the suffix
                }
        }

        // Convert the numeric part
        size_val = strtoul(str_copy, &endptr, 10);

        // Check if the conversion was successful
        if (*endptr != '\0' && *endptr != 'K' && *endptr != 'M' && *endptr != 'k' &&
            *endptr != 'm') {
                // Invalid characters in the string
                free(str_copy);
                return 0;
        }

        free(str_copy);
        return size_val * multiplier;
}

static void
print_help(void)
{
        printf("Usage: aes_perf [options]\n"
               "  -h, --help          Show this help message\n"
               "  -s, --size SIZE     Set buffer size for tests\n"
               "                      Size values can include K (KB) or M (MB) suffix\n"
               "                      Examples: --size 8K, --size 1M, --size 16384\n"
               "                      Range format: --size start:end[:step]\n"
               "                      Examples: --size 1K:8K (doubles each step)\n"
               "                                --size 1K:8K:1K (1K increments)\n"
               "                      If no size option is provided, default size (%d) is used\n"
               "  --with-openssl      Enable OpenSSL benchmarks for comparison\n"
               "  --op OPERATION      Set operation mode (encrypt/decrypt)\n"
               "                      Available operations: encrypt (enc), decrypt (dec)\n"
               "                      Default: encrypt\n"
               "  --csv               Output results in CSV format\n"
               "                      Format: "
               "algorithm,operation,buffer_size,library,throughput_MBps\n"
               "  --in-place          Use in-place operations (input and output buffers are the "
               "same)\n"
               "                      Default: out-of-place operations\n"
               "  -i, --iterations N  Set number of iterations for performance tests\n"
               "                      Default values: CBC=400000, GCM=400000, XTS=3000000\n"
               "  --alignment N       Set buffer alignment in bytes (must be power of 2 or 0)\n"
               "                      Default: 64 bytes\n"
               "                      Use 0 for default system alignment (malloc)\n"
               "                      Examples: --alignment 16, --alignment 128, --alignment 0\n"
               "  --aad-length N      Set AAD length for GCM operations (0-256 bytes)\n"
               "                      Default: 20 bytes\n"
               "  --cold              Enable cold cache testing (randomize buffer offsets)\n"
               "                      Uses large memory buffer to simulate cold cache conditions\n"
               "\n"
               "Algorithm Options:\n"
               "  --algo ALGORITHM    Run specific algorithm test\n"
               "                      Available algorithms:\n"
               "                        aes-cbc-128, aes-cbc-192, aes-cbc-256\n"
               "                        aes-gcm-128, aes-gcm-256\n"
               "                        aes-xts-128, aes-xts-256\n"
               "\n",
               DEFAULT_TEST_LEN);
}

// Algorithm type enumeration
typedef enum {
        ALGO_NONE = 0,
        ALGO_CBC_128,
        ALGO_CBC_192,
        ALGO_CBC_256,
        ALGO_GCM_128,
        ALGO_GCM_256,
        ALGO_XTS_128,
        ALGO_XTS_256
} algo_type_t;

// Helper function to parse algorithm string
static algo_type_t
parse_algorithm(const char *algo_str)
{
        if (!algo_str)
                return ALGO_NONE;

        // Specific algorithm variants
        if (strcasecmp(algo_str, "aes-cbc-128") == 0)
                return ALGO_CBC_128;
        if (strcasecmp(algo_str, "aes-cbc-192") == 0)
                return ALGO_CBC_192;
        if (strcasecmp(algo_str, "aes-cbc-256") == 0)
                return ALGO_CBC_256;
        if (strcasecmp(algo_str, "aes-gcm-128") == 0)
                return ALGO_GCM_128;
        if (strcasecmp(algo_str, "aes-gcm-256") == 0)
                return ALGO_GCM_256;
        if (strcasecmp(algo_str, "aes-xts-128") == 0)
                return ALGO_XTS_128;
        if (strcasecmp(algo_str, "aes-xts-256") == 0)
                return ALGO_XTS_256;

        return ALGO_NONE;
}

// Helper function to parse operation mode from command line argument
static operation_mode_t
parse_operation(const char *op_str)
{
        if (strcasecmp(op_str, "encrypt") == 0 || strcasecmp(op_str, "enc") == 0)
                return OP_ENCRYPT;
        if (strcasecmp(op_str, "decrypt") == 0 || strcasecmp(op_str, "dec") == 0)
                return OP_DECRYPT;

        return OP_ENCRYPT; // Default to encrypt for invalid input
}

// Helper function to parse size range from command line argument
// Supports formats: "start:end" or "start:end:step"
static int
parse_size_range(const char *range_str, size_range_t *range)
{
        char *str_copy = strdup(range_str);
        char *start_str, *end_str, *step_str;
        char *saveptr;

        if (!str_copy || !range) {
                free(str_copy);
                return 0;
        }

        // Parse start size
        start_str = strtok_r(str_copy, ":", &saveptr);
        if (!start_str) {
                free(str_copy);
                return 0;
        }

        // Parse end size
        end_str = strtok_r(NULL, ":", &saveptr);
        if (!end_str) {
                // No colon found, treat as single size
                size_t single_size = parse_size_value(start_str);
                if (single_size > 0) {
                        range->start_size = single_size;
                        range->end_size = single_size;
                        range->step_size = 0;
                        range->use_range = 0;
                        free(str_copy);
                        return 1;
                }
                free(str_copy);
                return 0;
        }

        // Parse optional step size
        step_str = strtok_r(NULL, ":", &saveptr);

        // Parse the start and end sizes
        range->start_size = parse_size_value(start_str);
        range->end_size = parse_size_value(end_str);

        if (range->start_size == 0 || range->end_size == 0 || range->start_size > range->end_size) {
                free(str_copy);
                return 0;
        }

        // Parse step size or use default
        if (step_str) {
                range->step_size = parse_size_value(step_str);
                if (range->step_size == 0) {
                        free(str_copy);
                        return 0;
                }
        } else
                // Default step: use 0 to indicate doubling mode
                range->step_size = 0;

        range->use_range = 1;
        free(str_copy);
        return 1;
}

// Helper function to parse and validate buffer alignment
// Alignment must be a power of 2 and at least sizeof(void*), or 0 for default malloc alignment
static int
parse_alignment(const char *align_str, size_t *alignment)
{
        char *endptr;
        unsigned long align_val = strtoul(align_str, &endptr, 10);

        // Check if conversion was successful
        if (*endptr != '\0') {
                return 0;
        }

        // Allow zero alignment (use malloc instead of posix_memalign)
        if (align_val == 0) {
                *alignment = 0;
                return 1;
        }

        // Check if it's a power of 2
        if ((align_val & (align_val - 1)) != 0) {
                return 0;
        }

        // Check minimum alignment requirement for posix_memalign
        if (align_val < sizeof(void *)) {
                return 0;
        }

        *alignment = (size_t) align_val;
        return 1;
}

// Helper function to calculate throughput in MB/s from performance data
static double
calculate_throughput_mbps(const struct perf start, const struct perf stop, const long long bytes)
{
        const long long secs = stop.tv.tv_sec - start.tv.tv_sec;
        const long long runtime_usecs = secs * 1000000 + stop.tv.tv_usec - start.tv.tv_usec;
        if (runtime_usecs <= 0)
                return 0.0;

        const double runtime_secs = runtime_usecs / 1000000.0;
        const double mbytes = bytes / (1024.0 * 1024.0);
        return mbytes / runtime_secs;
}

// Helper function to print CSV output
static void
print_csv_result(const char *const algorithm, const size_t buffer_size, const char *const operation,
                 const struct perf start, const struct perf stop, const long long bytes,
                 const char *const library)
{
        const double throughput = calculate_throughput_mbps(start, stop, bytes);
        printf("%s,%s,%zu,%s,%.2f\n", algorithm, operation, buffer_size, library, throughput);
}

// Function to determine maximum buffer size needed
static size_t
get_max_buffer_size(void)
{
        if (size_range.use_range) {
                return size_range.end_size;
        } else {
                return size_range.start_size;
        }
}

static int
allocate_buffers(const size_t max_size)
{
        int ret = 0;

        if (buffer_alignment == 0) {
                // Use malloc for default system alignment
                plaintext = malloc(max_size);
                ciphertext = malloc(max_size);

                if (!plaintext || !ciphertext) {
                        printf("Failed to allocate test buffers of size: %zu with default "
                               "alignment\n",
                               max_size);
                        return 1;
                }
        } else {
                // Use posix_memalign for specific alignment
                ret |= posix_memalign((void **) &plaintext, buffer_alignment, max_size);
                ret |= posix_memalign((void **) &ciphertext, buffer_alignment, max_size);

                if (ret != 0 || !plaintext || !ciphertext) {
                        printf("Failed to allocate test buffers of size: %zu with %zu-byte "
                               "alignment\n",
                               max_size, buffer_alignment);
                        return 1;
                }
        }

        return 0;
}

static void
free_buffers(void)
{
        if (buffer_alignment == 0) {
                free(plaintext);
                free(ciphertext);
        } else {
                aligned_free(plaintext);
                aligned_free(ciphertext);
        }
}

static void
mk_rand_data(uint8_t *data, const uint32_t size)
{
        unsigned int i;
        uint8_t init_value = rand();

        for (i = 0; i < size; i++)
                *data++ = init_value++;
}

// Helper functions for in-place vs out-of-place operations
static void
get_buffers_for_encrypt(unsigned char **input_buf, unsigned char **output_buf)
{
        if (in_place) {
                // In-place: use the same buffer for input and output
                *input_buf = plaintext;
                *output_buf = plaintext; // Same as input for in-place
        } else {
                // Out-of-place: use separate buffers
                *input_buf = plaintext;
                *output_buf = ciphertext;
        }
}

static void
get_buffers_for_decrypt(unsigned char **input_buf, unsigned char **output_buf)
{
        if (in_place) {
                // In-place: use the same buffer for input and output
                // For decrypt, we start with ciphertext and decrypt in-place
                *input_buf = ciphertext;
                *output_buf = ciphertext; // Same as input for in-place
        } else {
                // Out-of-place: use separate buffers
                *input_buf = ciphertext;
                *output_buf = plaintext;
        }
}

// Unified CBC function that handles all key sizes
static int
run_cbc(const size_t test_len, const int key_bits)
{
        int i, ret = 0;
        const int loop_count = custom_iterations ? custom_iterations : CBC_TEST_LOOPS;
        uint8_t *iv = NULL;
        struct isal_cbc_key_data *key_data = NULL;
        struct perf start, stop;
        uint8_t *key_ptr;
        const char *algorithm_name;
        unsigned char *input_buf, *output_buf;

        // Select key pointer and algorithm name based on key size
        switch (key_bits) {
        case 128:
                key_ptr = test_key_128;
                algorithm_name = "aes-cbc-128";
                break;
        case 192:
                key_ptr = test_key_192;
                algorithm_name = "aes-cbc-192";
                break;
        case 256:
                key_ptr = test_key_256;
                algorithm_name = "aes-cbc-256";
                break;
        default:
                printf("Unsupported key size: %d\n", key_bits);
                return 1;
        }

        if (!csv_output)
                printf("\n=== AES-%d-CBC Performance Test ===\n", key_bits);

        ret = posix_memalign((void **) &iv, 16, ISAL_CBC_IV_DATA_LEN);
        if (ret) {
                printf("CBC: alloc error for IV\n");
                return 1;
        }

        ret = posix_memalign((void **) &key_data, 16, sizeof(*key_data));
        if (ret) {
                printf("CBC: alloc error for key_data\n");
                aligned_free(iv);
                return 1;
        }

        // Key expansion based on key size
        switch (key_bits) {
        case 128:
                isal_aes_keyexp_128(key_ptr, key_data->enc_keys, key_data->dec_keys);
                break;
        case 192:
                isal_aes_keyexp_192(key_ptr, key_data->enc_keys, key_data->dec_keys);
                break;
        case 256:
                isal_aes_keyexp_256(key_ptr, key_data->enc_keys, key_data->dec_keys);
                break;
        }

        // Get appropriate buffers based on operation mode
        if (operation_mode == OP_ENCRYPT) {
                get_buffers_for_encrypt(&input_buf, &output_buf);
        } else {
                get_buffers_for_decrypt(&input_buf, &output_buf);
        }

        // Store base pointers for cold cache test
        unsigned char *base_input_buf = input_buf;
        unsigned char *base_output_buf = output_buf;
        uint64_t offset = 0;

        // ISA-L CBC test
        perf_start(&start);
        for (i = 0; i < loop_count; i++) {
                if (operation_mode == OP_ENCRYPT) {
                        switch (key_bits) {
                        case 128:
                                isal_aes_cbc_enc_128(input_buf, iv, key_data->enc_keys, output_buf,
                                                     test_len);
                                break;
                        case 192:
                                isal_aes_cbc_enc_192(input_buf, iv, key_data->enc_keys, output_buf,
                                                     test_len);
                                break;
                        case 256:
                                isal_aes_cbc_enc_256(input_buf, iv, key_data->enc_keys, output_buf,
                                                     test_len);
                                break;
                        }
                } else {
                        switch (key_bits) {
                        case 128:
                                isal_aes_cbc_dec_128(input_buf, iv, key_data->dec_keys, output_buf,
                                                     test_len);
                                break;
                        case 192:
                                isal_aes_cbc_dec_192(input_buf, iv, key_data->dec_keys, output_buf,
                                                     test_len);
                                break;
                        case 256:
                                isal_aes_cbc_dec_256(input_buf, iv, key_data->dec_keys, output_buf,
                                                     test_len);
                                break;
                        }
                }
                if (cold_test) {
                        offset = (uint64_t) rand() % (TEST_LARGE_MEM_LEN - test_len);
                        input_buf = base_input_buf + offset;
                        output_buf = base_output_buf + offset;
                }
        }
        perf_stop(&stop);
        if (csv_output) {
                const char *op_name = (operation_mode == OP_ENCRYPT) ? "encrypt" : "decrypt";
                print_csv_result(algorithm_name, test_len, op_name, start, stop,
                                 (long long) test_len * i, "ISA-L");
        } else {
                const char *op_type = (operation_mode == OP_ENCRYPT) ? "encode" : "decode";
                printf("ISA-L_aes_cbc_%d_%s:  ", key_bits, op_type);
                perf_print(stop, start, (long long) test_len * i);
        }

        // OpenSSL CBC test
        if (enable_openssl) {
                // Reset buffer pointers
                input_buf = base_input_buf;
                output_buf = base_output_buf;
                perf_start(&start);
                for (i = 0; i < loop_count; i++) {
                        if (operation_mode == OP_ENCRYPT) {
                                switch (key_bits) {
                                case 128:
                                        openssl_aes_128_cbc_enc(key_ptr, iv, test_len, input_buf,
                                                                output_buf);
                                        break;
                                case 192:
                                        openssl_aes_192_cbc_enc(key_ptr, iv, test_len, input_buf,
                                                                output_buf);
                                        break;
                                case 256:
                                        openssl_aes_256_cbc_enc(key_ptr, iv, test_len, input_buf,
                                                                output_buf);
                                        break;
                                }
                        } else {
                                switch (key_bits) {
                                case 128:
                                        openssl_aes_128_cbc_dec(key_ptr, iv, test_len, input_buf,
                                                                output_buf);
                                        break;
                                case 192:
                                        openssl_aes_192_cbc_dec(key_ptr, iv, test_len, input_buf,
                                                                output_buf);
                                        break;
                                case 256:
                                        openssl_aes_256_cbc_dec(key_ptr, iv, test_len, input_buf,
                                                                output_buf);
                                        break;
                                }
                        }
                        if (cold_test) {
                                offset = (uint64_t) rand() % (TEST_LARGE_MEM_LEN - test_len);
                                input_buf = base_input_buf + offset;
                                output_buf = base_output_buf + offset;
                        }
                }
                perf_stop(&stop);
                if (csv_output) {
                        const char *op_name =
                                (operation_mode == OP_ENCRYPT) ? "encrypt" : "decrypt";
                        print_csv_result(algorithm_name, test_len, op_name, start, stop,
                                         (long long) test_len * i, "OpenSSL");
                } else {
                        const char *op_type = (operation_mode == OP_ENCRYPT) ? "encode" : "decode";
                        printf("OpenSSL_aes_cbc_%d_%s: ", key_bits, op_type);
                        perf_print(stop, start, (long long) test_len * i);
                }
        }

        aligned_free(iv);
        aligned_free(key_data);
        return 0;
}

// Unified GCM function that handles both 128 and 256 bit keys
static int
run_gcm(const size_t test_len, const int key_bits)
{
        int i;
        const int loop_count = custom_iterations ? custom_iterations : GCM_TEST_LOOPS;
        struct isal_gcm_key_data gkey;
        struct isal_gcm_context_data gctx;
        uint8_t key[32]; // Allocate maximum size for both 128 and 256 bit keys
        uint8_t IV[ISAL_GCM_IV_LEN];
        uint8_t AAD[MAX_AAD_LEN];
        uint8_t gcm_tag[16];
        const uint32_t iv_len = ISAL_GCM_IV_LEN;
        const char *algorithm_name;
        const char *isal_enc_label, *isal_dec_label;
        const int key_size = (key_bits == 128) ? 16 : 32;
        struct perf start, stop;

        // Set parameters based on key size
        switch (key_bits) {
        case 128:
                algorithm_name = "aes-gcm-128";
                isal_enc_label = "        isal_aes_gcm_enc:\t";
                isal_dec_label = "        isal_aes_gcm_dec:\t";
                break;
        case 256:
                algorithm_name = "aes-gcm-256";
                isal_enc_label = "         aes_gcm256_enc:\t";
                isal_dec_label = "         aes_gcm256_dec:\t";
                break;
        default:
                printf("Unsupported GCM key size: %d\n", key_bits);
                return 1;
        }

        if (!csv_output) {
                printf("\n=== AES-%d-GCM Performance Test ===\n", key_bits);
                printf("Parameters: text_len:%zu; IV_len:%d; AAD_len:%d\n", test_len,
                       ISAL_GCM_IV_LEN, 20);
        }

        mk_rand_data(key, key_size);
        mk_rand_data(IV, sizeof(IV));
        mk_rand_data(AAD, sizeof(AAD));

        // Key expansion based on key size
        if (key_bits == 128)
                isal_aes_gcm_pre_128(key, &gkey);
        else
                isal_aes_gcm_pre_256(key, &gkey);

        // Get appropriate buffers based on operation mode
        unsigned char *input_buf, *output_buf;
        if (operation_mode == OP_ENCRYPT) {
                get_buffers_for_encrypt(&input_buf, &output_buf);
        } else {
                get_buffers_for_decrypt(&input_buf, &output_buf);
        }
        unsigned char *base_input_buf = input_buf;
        unsigned char *base_output_buf = output_buf;
        uint64_t offset = 0;

        // ISA-L GCM test
        perf_start(&start);
        for (i = 0; i < loop_count; i++) {
                if (operation_mode == OP_ENCRYPT) {
                        if (key_bits == 128) {
                                isal_aes_gcm_enc_128(&gkey, &gctx, output_buf, input_buf, test_len,
                                                     IV, AAD, aad_length, gcm_tag, 16);
                        } else {
                                isal_aes_gcm_enc_256(&gkey, &gctx, output_buf, input_buf, test_len,
                                                     IV, AAD, aad_length, gcm_tag, 16);
                        }
                } else {
                        if (key_bits == 128) {
                                isal_aes_gcm_dec_128(&gkey, &gctx, output_buf, input_buf, test_len,
                                                     IV, AAD, aad_length, gcm_tag, 16);
                        } else {
                                isal_aes_gcm_dec_256(&gkey, &gctx, output_buf, input_buf, test_len,
                                                     IV, AAD, aad_length, gcm_tag, 16);
                        }
                }
                if (cold_test) {
                        offset = (uint64_t) rand() % (TEST_LARGE_MEM_LEN - test_len);
                        input_buf = base_input_buf + offset;
                        output_buf = base_output_buf + offset;
                }
        }
        perf_stop(&stop);
        if (csv_output) {
                const char *op_name = (operation_mode == OP_ENCRYPT) ? "encrypt" : "decrypt";
                print_csv_result(algorithm_name, test_len, op_name, start, stop,
                                 (long long) test_len * i, "ISA-L");
        } else {
                const char *label =
                        (operation_mode == OP_ENCRYPT) ? isal_enc_label : isal_dec_label;
                printf("%s", label);
                perf_print(stop, start, (long long) test_len * i);
        }

        // OpenSSL GCM test
        if (enable_openssl) {
                // Reset buffer pointers
                input_buf = base_input_buf;
                output_buf = base_output_buf;
                perf_start(&start);
                for (i = 0; i < loop_count; i++) {
                        if (operation_mode == OP_ENCRYPT) {
                                if (key_bits == 128) {
                                        openssl_aes_gcm_enc(key, IV, iv_len, AAD, aad_length,
                                                            gcm_tag, 16, input_buf, test_len,
                                                            output_buf);
                                } else {
                                        openssl_aes_256_gcm_enc(key, IV, iv_len, AAD, aad_length,
                                                                gcm_tag, 16, input_buf, test_len,
                                                                output_buf);
                                }
                        } else {
                                if (key_bits == 128) {
                                        openssl_aes_gcm_dec(key, IV, iv_len, AAD, aad_length,
                                                            gcm_tag, 16, input_buf, test_len,
                                                            output_buf);
                                } else {
                                        openssl_aes_256_gcm_dec(key, IV, iv_len, AAD, aad_length,
                                                                gcm_tag, 16, input_buf, test_len,
                                                                output_buf);
                                }
                        }
                        if (cold_test) {
                                offset = (uint64_t) rand() % (TEST_LARGE_MEM_LEN - test_len);
                                input_buf = base_input_buf + offset;
                                output_buf = base_output_buf + offset;
                        }
                }
                perf_stop(&stop);
                if (csv_output) {
                        const char *op_name =
                                (operation_mode == OP_ENCRYPT) ? "encrypt" : "decrypt";
                        print_csv_result(algorithm_name, test_len, op_name, start, stop,
                                         (long long) test_len * i, "OpenSSL");
                } else {
                        const char *op_type = (operation_mode == OP_ENCRYPT) ? "enc" : "dec";
                        if (key_bits == 128) {
                                printf("openssl_aes_gcm_%s:\t", op_type);
                        } else {
                                printf("openssl_aes_256_gcm_%s:\t", op_type);
                        }
                        perf_print(stop, start, (long long) test_len * i);
                }
        }

        return 0;
}

// Unified XTS function that handles both 128 and 256 bit keys
static int
run_xts(const size_t test_len, const int key_bits)
{
        int i;
        const int loop_count = custom_iterations ? custom_iterations : XTS_TEST_LOOPS;
        const int loop_count_ossl = loop_count / 10;        // Reduced iterations for OpenSSL
        unsigned char key1[32], key2[32], tinit[16];        // 32 bytes for max key size
        unsigned char keyssl[64];                           /* SSL takes both keys together */
        uint8_t expkey1_enc[16 * 15], expkey2_enc[16 * 15]; // Max size for 256-bit
        uint8_t expkey1_dec[16 * 15], expkey2_dec[16 * 15];
        const int key_size = (key_bits == 128) ? 16 : 32;
        const char *const algorithm_name = (key_bits == 128) ? "aes-xts-128" : "aes-xts-256";
        const char *const expanded_name =
                (key_bits == 128) ? "aes-xts-128-expanded" : "aes-xts-256-expanded";
        struct perf start, stop;
        uint8_t *in_buf, *out_buf;

        if (!csv_output)
                printf("\n=== AES XTS-%d Performance Tests ===\n", key_bits);

        // Generate random keys
        mk_rand_data(key1, key_size);
        mk_rand_data(key2, key_size);
        mk_rand_data(tinit, 16);

        // Expand keys for expanded key API tests
        if (key_bits == 128) {
                isal_aes_keyexp_128(key1, expkey1_enc, expkey1_dec);
                isal_aes_keyexp_128(key2, expkey2_enc, expkey2_dec);
        } else {
                isal_aes_keyexp_256(key1, expkey1_enc, expkey1_dec);
                isal_aes_keyexp_256(key2, expkey2_enc, expkey2_dec);
        }

        /* Set up key for the SSL engine */
        for (i = 0; i < key_size; i++) {
                keyssl[i] = key1[i];
                keyssl[i + key_size] = key2[i];
        }

        // Get appropriate buffers based on operation mode
        if (operation_mode == OP_ENCRYPT) {
                get_buffers_for_encrypt(&in_buf, &out_buf);
        } else {
                get_buffers_for_decrypt(&in_buf, &out_buf);
        }

        // Store base pointers for cold cache test
        uint8_t *base_in_buf = in_buf;
        uint8_t *base_out_buf = out_buf;
        uint64_t offset = 0;

        // XTS regular API test
        perf_start(&start);
        for (i = 0; i < loop_count; i++) {
                if (operation_mode == OP_ENCRYPT) {
                        if (key_bits == 128) {
                                isal_aes_xts_enc_128(key2, key1, tinit, test_len, in_buf, out_buf);
                        } else {
                                isal_aes_xts_enc_256(key2, key1, tinit, test_len, in_buf, out_buf);
                        }
                } else {
                        if (key_bits == 128) {
                                isal_aes_xts_dec_128(key2, key1, tinit, test_len, in_buf, out_buf);
                        } else {
                                isal_aes_xts_dec_256(key2, key1, tinit, test_len, in_buf, out_buf);
                        }
                }
                if (cold_test) {
                        offset = (uint64_t) rand() % (TEST_LARGE_MEM_LEN - test_len);
                        in_buf = base_in_buf + offset;
                        out_buf = base_out_buf + offset;
                }
        }
        perf_stop(&stop);
        if (csv_output) {
                const char *op_name = (operation_mode == OP_ENCRYPT) ? "encrypt" : "decrypt";
                print_csv_result(algorithm_name, test_len, op_name, start, stop,
                                 (long long) test_len * i, "ISA-L");
        } else {
                const char *op_type = (operation_mode == OP_ENCRYPT) ? "enc" : "dec";
                printf("aes_xts_%d_%s:\t", key_bits, op_type);
                perf_print(stop, start, (long long) test_len * i);
        }

        // XTS expanded key API test
        in_buf = base_in_buf; // Reset to base for expanded key test
        out_buf = base_out_buf;
        perf_start(&start);
        for (i = 0; i < loop_count; i++) {
                if (operation_mode == OP_ENCRYPT) {
                        if (key_bits == 128) {
                                isal_aes_xts_enc_128_expanded_key(expkey2_enc, expkey1_enc, tinit,
                                                                  test_len, in_buf, out_buf);
                        } else {
                                isal_aes_xts_enc_256_expanded_key(expkey2_enc, expkey1_enc, tinit,
                                                                  test_len, in_buf, out_buf);
                        }
                } else {
                        if (key_bits == 128) {
                                isal_aes_xts_dec_128_expanded_key(expkey2_enc, expkey1_dec, tinit,
                                                                  test_len, in_buf, out_buf);
                        } else {
                                isal_aes_xts_dec_256_expanded_key(expkey2_enc, expkey1_dec, tinit,
                                                                  test_len, in_buf, out_buf);
                        }
                }
                if (cold_test) {
                        offset = (uint64_t) rand() % (TEST_LARGE_MEM_LEN - test_len);
                        in_buf = base_in_buf + offset;
                        out_buf = base_out_buf + offset;
                }
        }
        perf_stop(&stop);
        if (csv_output) {
                const char *op_name = (operation_mode == OP_ENCRYPT) ? "encrypt" : "decrypt";
                print_csv_result(expanded_name, test_len, op_name, start, stop,
                                 (long long) test_len * i, "ISA-L");
        } else {
                const char *op_type = (operation_mode == OP_ENCRYPT) ? "enc" : "dec";
                printf("aes_xts_%d_%s_expanded:\t", key_bits, op_type);
                perf_print(stop, start, (long long) test_len * i);
        }

        // XTS OpenSSL test
        if (enable_openssl) {
                in_buf = base_in_buf; // Reset to base for OpenSSL
                out_buf = base_out_buf;
                EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                if (!ctx) {
                        printf("Failed to create EVP_CIPHER_CTX\n");
                        return 1;
                }

                perf_start(&start);
                for (i = 0; i < loop_count_ossl; i++) {
                        if (operation_mode == OP_ENCRYPT) {
                                if (key_bits == 128) {
                                        openssl_aes_128_xts_enc(ctx, keyssl, tinit, test_len,
                                                                in_buf, out_buf);
                                } else {
                                        openssl_aes_256_xts_enc(ctx, keyssl, tinit, test_len,
                                                                in_buf, out_buf);
                                }
                        } else {
                                if (key_bits == 128) {
                                        openssl_aes_128_xts_dec(ctx, keyssl, tinit, test_len,
                                                                in_buf, out_buf);
                                } else {
                                        openssl_aes_256_xts_dec(ctx, keyssl, tinit, test_len,
                                                                in_buf, out_buf);
                                }
                        }
                        if (cold_test) {
                                offset = (uint64_t) rand() % (TEST_LARGE_MEM_LEN - test_len);
                                in_buf = base_in_buf + offset;
                                out_buf = base_out_buf + offset;
                        }
                }
                perf_stop(&stop);
                if (csv_output) {
                        const char *op_name =
                                (operation_mode == OP_ENCRYPT) ? "encrypt" : "decrypt";
                        print_csv_result(algorithm_name, test_len, op_name, start, stop,
                                         (long long) test_len * i, "OpenSSL");
                } else {
                        const char *op_type = (operation_mode == OP_ENCRYPT) ? "enc" : "dec";
                        printf("openssl_aes_xts_%d_%s:\t", key_bits, op_type);
                        perf_print(stop, start, (long long) test_len * i);
                }

                EVP_CIPHER_CTX_free(ctx);
        }

        return 0;
}

// Function to run a specific algorithm
static int
run_specific_algorithm(const algo_type_t algo, const size_t test_len)
{
        switch (algo) {
        case ALGO_CBC_128:
                return run_cbc(test_len, 128);
        case ALGO_CBC_192:
                return run_cbc(test_len, 192);
        case ALGO_CBC_256:
                return run_cbc(test_len, 256);
        case ALGO_GCM_128:
                return run_gcm(test_len, 128);
        case ALGO_GCM_256:
                return run_gcm(test_len, 256);
        case ALGO_XTS_128:
                return run_xts(test_len, 128);
        case ALGO_XTS_256:
                return run_xts(test_len, 256);
        default:
                printf("Unknown algorithm\n");
                return 1;
        }
}

int
main(int argc, char *argv[])
{
        int fail = 0;
        algo_type_t selected_algorithm = ALGO_NONE;
        size_t test_len = DEFAULT_TEST_LEN;
        aad_length = DEFAULT_AAD_LEN;

        // Parse command line arguments
        for (int i = 1; i < argc; i++) {
                // Help option
                if (strcasecmp(argv[i], "-h") == 0 || strcasecmp(argv[i], "--help") == 0) {
                        print_help();
                        return 0;
                }
                // Enable OpenSSL option
                else if (strcasecmp(argv[i], "--with-openssl") == 0) {
                        enable_openssl = 1;
                        if (!csv_output) {
                                printf("OpenSSL benchmarks enabled\n");
                        }
                }
                // Algorithm option
                else if (strcasecmp(argv[i], "--algo") == 0) {
                        if (i + 1 < argc && argv[i + 1][0] != '-') {
                                // Option has an argument
                                i++; // Move to the argument
                                const char *algo_arg = argv[i];

                                // Check if algorithm was already specified
                                if (selected_algorithm != ALGO_NONE) {
                                        printf("Error: Only one algorithm can be specified with "
                                               "--algo option.\n");
                                        return 1;
                                }

                                algo_type_t algo = parse_algorithm(algo_arg);
                                if (algo != ALGO_NONE) {
                                        selected_algorithm = algo;
                                        if (!csv_output) {
                                                printf("Selected algorithm: %s\n", algo_arg);
                                        }
                                } else {
                                        printf("Invalid algorithm: '%s'. Use --help to see "
                                               "available algorithms.\n",
                                               algo_arg);
                                        return 1;
                                }
                        } else {
                                printf("Option --algo requires an argument.\n");
                                print_help();
                                return 1;
                        }
                }
                // Size option with separate argument format (-s VALUE or --size VALUE)
                else if (strcasecmp(argv[i], "-s") == 0 || strcasecmp(argv[i], "--size") == 0) {
                        if (i + 1 < argc && argv[i + 1][0] != '-') {
                                // Option has an argument
                                i++; // Move to the argument
                                const char *size_arg = argv[i];
                                if (parse_size_range(size_arg, &size_range)) {
                                        if (size_range.use_range) {
                                                if (size_range.step_size == 0) {
                                                        printf("Using size range: %zu to %zu bytes "
                                                               "(doubling)\n",
                                                               size_range.start_size,
                                                               size_range.end_size);
                                                } else {
                                                        printf("Using size range: %zu to %zu bytes "
                                                               "(step: %zu)\n",
                                                               size_range.start_size,
                                                               size_range.end_size,
                                                               size_range.step_size);
                                                }
                                        } else {
                                                test_len = size_range.start_size;
                                                printf("Using buffer size: %zu bytes\n", test_len);
                                        }
                                } else {
                                        printf("Invalid size value: '%s'. Using default size.\n",
                                               size_arg);
                                }
                        } else {
                                printf("Option --size requires an argument.\n");
                                print_help();
                                return 1;
                        }
                }
                // Operation mode option
                else if (strcasecmp(argv[i], "--op") == 0) {
                        if (i + 1 < argc && argv[i + 1][0] != '-') {
                                // Option has an argument
                                i++; // Move to the argument
                                const char *op_arg = argv[i];
                                operation_mode_t op = parse_operation(op_arg);
                                operation_mode = op;
                                if (!csv_output) {
                                        printf("Operation mode: %s\n",
                                               (op == OP_ENCRYPT) ? "encrypt" : "decrypt");
                                }
                        } else {
                                printf("Option --op requires an argument.\n");
                                print_help();
                                return 1;
                        }
                }
                // CSV output option
                else if (strcasecmp(argv[i], "--csv") == 0)
                        csv_output = 1;
                // In-place operations option
                else if (strcasecmp(argv[i], "--in-place") == 0)
                        in_place = 1;
                // Cold test option
                else if (strcmp(argv[i], "--cold") == 0) {
                        cold_test = 1;
                        if (!csv_output) {
                                printf("Cold cache testing enabled\n");
                        }
                }
                // Iterations option
                else if (strcasecmp(argv[i], "-i") == 0 ||
                         strcasecmp(argv[i], "--iterations") == 0) {
                        if (i + 1 < argc && argv[i + 1][0] != '-') {
                                // Option has an argument
                                i++; // Move to the argument
                                const char *const iter_arg = argv[i];
                                char *endptr;
                                const long iter_val = strtol(iter_arg, &endptr, 10);

                                if (*endptr == '\0' && iter_val > 0 && iter_val <= INT_MAX) {
                                        custom_iterations = (int) iter_val;
                                        if (!csv_output) {
                                                printf("Using %d iterations for all tests\n",
                                                       custom_iterations);
                                        }
                                } else {
                                        printf("Invalid iterations value: '%s'. Must be a positive "
                                               "integer.\n",
                                               iter_arg);
                                        return 1;
                                }
                        } else {
                                printf("Option --iterations requires an argument.\n");
                                print_help();
                                return 1;
                        }
                }
                // Alignment option
                else if (strcmp(argv[i], "--alignment") == 0) {
                        if (i + 1 < argc && argv[i + 1][0] != '-') {
                                // Option has an argument
                                i++; // Move to the argument
                                const char *align_arg = argv[i];
                                size_t new_alignment;

                                if (parse_alignment(align_arg, &new_alignment)) {
                                        buffer_alignment = new_alignment;
                                        if (!csv_output) {
                                                printf("Using buffer alignment: %zu bytes\n",
                                                       buffer_alignment);
                                        }
                                } else {
                                        printf("Invalid alignment value: '%s'. Must be a power of "
                                               "2 "
                                               "and at least %zu bytes.\n",
                                               align_arg, sizeof(void *));
                                        return 1;
                                }
                        } else {
                                printf("Option --alignment requires an argument.\n");
                                print_help();
                                return 1;
                        }
                }
                // AAD length option
                else if (strcasecmp(argv[i], "--aad-length") == 0) {
                        if (i + 1 < argc && argv[i + 1][0] != '-') {
                                // Option has an argument
                                i++; // Move to the argument
                                const char *const aad_arg = argv[i];
                                char *endptr;
                                const long aad_val = strtol(aad_arg, &endptr, 10);

                                if (*endptr == '\0' && aad_val >= 0 && aad_val <= MAX_AAD_LEN) {
                                        aad_length = (int) aad_val;
                                        if (!csv_output) {
                                                printf("Using AAD length: %d bytes\n", aad_length);
                                        }
                                } else {
                                        printf("Invalid AAD length value: '%s'. Must be between 0 "
                                               "and %d bytes.\n",
                                               aad_arg, MAX_AAD_LEN);
                                        return 1;
                                }
                        } else {
                                printf("Option --aad-length requires an argument.\n");
                                print_help();
                                return 1;
                        }
                }
                // Unknown option
                else if (argv[i][0] == '-') {
                        printf("Unknown option: %s\n", argv[i]);
                        print_help();
                        return 1;
                }
        }

        if (selected_algorithm == ALGO_NONE) {
                printf("Algorithm required. Use --algo option to specify an algorithm.\n");
                print_help();
                return 1;
        }
        srand(TEST_SEED);

        // Allocate buffers once for the maximum size needed
        const size_t max_buffer_size = (cold_test ? TEST_LARGE_MEM_LEN : get_max_buffer_size());

        // Validate that maximum test size is compatible with cold cache testing
        if (cold_test && get_max_buffer_size() >= TEST_LARGE_MEM_LEN) {
                printf("Error: Maximum test size (%zu) must be less than TEST_LARGE_MEM_LEN (%zu) "
                       "for cold cache testing\n",
                       get_max_buffer_size(), (size_t) TEST_LARGE_MEM_LEN);
                fail = 1;
                goto exit;
        }

        if (allocate_buffers(max_buffer_size)) {
                fail = 1;
                goto exit;
        }

        // Initialize test data
        mk_rand_data(plaintext, max_buffer_size);
        mk_rand_data(ciphertext, max_buffer_size);
        mk_rand_data(test_key_128, sizeof(test_key_128));
        mk_rand_data(test_key_192, sizeof(test_key_192));
        mk_rand_data(test_key_256, sizeof(test_key_256));
        mk_rand_data(test_iv, sizeof(test_iv));

        // Print CSV header or normal header
        if (csv_output)
                printf("algorithm,operation,buffer_size,library,throughput_MBps\n");
        else {
                printf("AES Consolidated Performance Test\n");
                if (in_place)
                        printf("Using in-place operations\n");
        }

        // Handle size ranges or single size using unified loop
        if (size_range.use_range) {
                if (!csv_output) {
                        if (size_range.step_size == 0) {
                                printf("Testing size range: %zu to %zu bytes (doubling)\n",
                                       size_range.start_size, size_range.end_size);
                        } else {
                                printf("Testing size range: %zu to %zu bytes (step: %zu)\n",
                                       size_range.start_size, size_range.end_size,
                                       size_range.step_size);
                        }
                }
        } else {
                // Single size test - treat as range with start == end
                if (!csv_output) {
                        printf("Test length: %zu bytes\n", size_range.start_size);
                }
        }

        // Unified loop for both single size and range testing
        for (size_t current_size = size_range.start_size; current_size <= size_range.end_size;) {

                if (!csv_output && size_range.use_range) {
                        printf("\n=== Testing with size: %zu bytes ===\n", current_size);
                }

                // Reinitialize test data for the new size (only the portion we'll use)
                mk_rand_data(plaintext, current_size);

                // Run specific algorithm
                fail += run_specific_algorithm(selected_algorithm, current_size);

                // For single size, break after first iteration
                if (!size_range.use_range) {
                        break;
                }

                // Calculate next size for range testing
                if (size_range.step_size == 0) {
                        // Doubling mode: double the current size
                        const size_t next_size = current_size * 2;
                        if (next_size > size_range.end_size) {
                                // If doubling overshoots, test the end size if we haven't already
                                if (current_size < size_range.end_size) {
                                        current_size = size_range.end_size;
                                } else {
                                        break;
                                }
                        } else {
                                current_size = next_size;
                        }
                } else {
                        // Fixed step mode: add the step size
                        current_size += size_range.step_size;
                }
        }

exit:
        free_buffers();
        return fail;
}
