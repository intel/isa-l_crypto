/**********************************************************************
  Copyright(c) 2022, Intel Corporation All rights reserved.

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
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <acvp/acvp.h>
#include <isa-l_crypto.h>

#if defined(__GNUC__) || defined(__clang__)
#define ATTRIBUTE(x) __attribute__((x))
#else
#define ATTRIBUTE(x)
#endif

int
enable_gcm(ACVP_CTX *ctx) ATTRIBUTE(weak);
int
enable_xts(ACVP_CTX *ctx) ATTRIBUTE(weak);
int
enable_cbc(ACVP_CTX *ctx) ATTRIBUTE(weak);
int
enable_sha(ACVP_CTX *ctx) ATTRIBUTE(weak);

uint8_t verbose = 0;

static ACVP_RESULT
logger(char *msg, ACVP_LOG_LVL level)
{
        if (level == ACVP_LOG_LVL_ERR)
                printf("[ERROR] ");
        else if (level == ACVP_LOG_LVL_WARN)
                printf("[WARNING] ");

        printf("%s\n", msg);
        return ACVP_SUCCESS;
}

static void
usage(void)
{
        fprintf(stderr,
                "Usage: acvp_app [options]\n\n"
                "Options:\n"
                "  -r, --req <file>     request file in JSON format\n"
                "  -p, --rsp <file>     response file in JSON format\n"
                "  -s, --server <name>  server name or ip address\n"
                "  -P, --port <num>     server port number\n"
                "  -h, --help           help, print this message\n"
                "  -v, --verbose        verbose, prints extra information\n\n"
                "Example:\n"
                " acvp_app -r AES-GCM-req.json -p AES-GCM-rsp.json  # Run from file only\n"
                " acvp_app                  # Connect to server at default 127.0.0.1:443\n\n");
}

int
main(int argc, char **argv)
{
        ACVP_CTX *ctx = NULL;
        ACVP_RESULT ret = ACVP_INVALID_ARG;
        ACVP_LOG_LVL log_level = ACVP_LOG_LVL_WARN;
        char *req_filename = NULL;
        char *rsp_filename = NULL;
        char *server = "127.0.0.1";
        int port = 443;
        char c;

        char optstring[] = "hvr:p:s:P:k:";
        struct option long_options[] = { { "help", no_argument, NULL, 'h' },
                                         { "verbose", no_argument, NULL, 'v' },
                                         { "req", required_argument, NULL, 'r' },
                                         { "rsp", required_argument, NULL, 'p' },
                                         { "server", required_argument, NULL, 's' },
                                         { "port", required_argument, NULL, 'P' },
                                         { 0, 0, 0, 0 } };

        opterr = 0;
        while ((c = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
                switch (c) {
                case 'v':
                        verbose++;
                        if (log_level < ACVP_LOG_LVL_MAX)
                                log_level++;
                        break;
                case 'r':
                        req_filename = optarg;
                        break;
                case 'p':
                        rsp_filename = optarg;
                        break;
                case 's':
                        server = optarg;
                        break;
                case 'P':
                        port = atoi(optarg);
                        break;
                case 'h':
                        ret = ACVP_SUCCESS;
                        /* fall through */
                default:
                        usage();
                        goto exit;
                        break;
                }
        }

        printf("ISA-L Crypto library version: %s\n", isal_crypto_get_version_str());
        printf("ACVP test app, ACVP library version(protocol version): %s(%s)\n", acvp_version(),
               acvp_protocol_version());

        // Create test session and enable tests
        ret = acvp_create_test_session(&ctx, logger, log_level);
        if (ret != ACVP_SUCCESS) {
                printf("Failed at create test session\n");
                goto exit;
        }

        ret = acvp_set_server(ctx, server, port);
        if (ret != ACVP_SUCCESS) {
                printf("Failed at set server\n");
                goto exit;
        }

        if (rsp_filename == NULL && req_filename != NULL)
                if (acvp_mark_as_request_only(ctx, req_filename))
                        goto exit;

        // Enable crypto modules
        ret = ACVP_UNSUPPORTED_OP;

        if (enable_gcm && enable_gcm(ctx))
                goto exit;
        if (enable_xts && enable_xts(ctx))
                goto exit;
        if (enable_cbc && enable_cbc(ctx))
                goto exit;
        if (enable_sha && enable_sha(ctx))
                goto exit;

        // Parse request file, run crypto tests and write out response file
        if (req_filename != NULL && rsp_filename != NULL) {
                ret = acvp_run_vectors_from_file(ctx, req_filename, rsp_filename);
                goto exit;
        }
        // Run the test session from server
        printf("Run on server %s:%d\n", server, port);
        char *api_context = getenv("ACV_API_CONTEXT");
        char *ca_chain_file = getenv("ACV_CA_FILE");
        char *cert_file = getenv("ACV_CERT_FILE");
        char *key_file = getenv("ACV_KEY_FILE");
        if (!api_context)
                api_context = "";

        ret = acvp_set_path_segment(ctx, "/acvp/v1/");
        ret |= acvp_set_api_context(ctx, api_context);
        if (ca_chain_file)
                ret |= acvp_set_cacerts(ctx, ca_chain_file);
        if (cert_file && key_file)
                ret |= acvp_set_certkey(ctx, cert_file, key_file);

        if (ret != ACVP_SUCCESS) {
                ret = ACVP_INVALID_ARG;
                goto exit;
        }

        ret = acvp_run(ctx, 0);

exit:
        if (ret)
                printf("ACVP app fail: %s\n", acvp_lookup_error_string(ret));

        acvp_cleanup(ctx);
        return ret;
}
