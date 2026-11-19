/*
 * Fuzz the OCSP-GET detection sslsplit applies to every HTTP GET request URI a
 * client sends through the proxy: pxy_ocsp_is_valid_uri() (pxyconn.c), which runs
 * percent-decoding (url_dec, url.c), base64 decoding (base64_dec, base64.c) and
 * OCSP request ASN.1 sniffing (ssl_is_ocspreq, ssl.c).
 *
 * pxy_ocsp_is_valid_uri() is static, so this file includes pxyconn.c and calls the
 * real function (build.sh links every project object except pxyconn.o). It only
 * sets ctx->enomem, so a zeroed context is enough.
 *
 * Input: the request URI (a C string in the proxy, from the parsed request line).
 * Coverage ceiling: the sslsplit code on this path is small (url_dec, base64_dec and
 * the first lines of ssl_is_ocspreq); the rest of ssl_is_ocspreq is OpenSSL's
 * d2i_OCSP_REQUEST, which is not instrumented. The `http` target reaches the same
 * function from full request headers. No state is kept across inputs.
 */
#include "../../pxyconn.c"

#include <stdint.h>

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	if (ssl_init() == -1)
		abort();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	pxy_conn_ctx_t ctx;
	char *uri;

	uri = malloc(size + 1);
	if (!uri)
		abort();
	memcpy(uri, data, size);
	uri[size] = '\0';

	memset(&ctx, 0, sizeof(ctx));
	(void)pxy_ocsp_is_valid_uri(uri, &ctx);

	free(uri);
	return 0;
}
