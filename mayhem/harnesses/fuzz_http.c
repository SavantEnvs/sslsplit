/*
 * Fuzz sslsplit's HTTP header munging, the code every proxied HTTP request and
 * response header line passes through (pxy_bev_readcb() in pxyconn.c):
 *   - pxy_http_reqhdr_filter_line(): parses the request line (method, URI),
 *     Host:, Content-Type:, rewrites Connection:, drops Upgrade:/Accept-Encoding:/
 *     Keep-Alive:
 *   - pxy_ocsp_is_valid_uri(): the OCSP-GET check the proxy runs on the request
 *     URI once the request header is complete (url_dec -> base64_dec ->
 *     ssl_is_ocspreq), with the same GET guard as pxy_ocsp_deny()
 *   - pxy_http_resphdr_filter_line(): parses the status line, Content-Length:,
 *     drops HPKP/HSTS/Expect-CT/Alternate-Protocol/Upgrade
 *
 * The three functions are static, so this file includes pxyconn.c and calls the
 * real code (build.sh links every project object except pxyconn.o). They only
 * read and write the ctx->http_* fields and flags, never the bufferevents, so a
 * zeroed pxy_conn_ctx_t is all they need.
 *
 * Input: the bytes the client sends (request header), followed by the bytes the
 * server sends back (response header). Lines are split with libevent's
 * evbuffer_readln(EVBUFFER_EOL_CRLF), as in pxy_bev_readcb(): request lines go
 * through the request filter until it reports the header complete, the rest
 * through the response filter. Each input gets a fresh context, freed at the end.
 *
 * Coverage ceiling (about 90-111 edges): the code reached here is small. The two
 * filters are ~170 lines that are mostly a flat chain of strncasecmp() header
 * checks, plus enomem branches that only a failing malloc reaches. The OCSP leg is
 * url_dec + base64_dec, then OpenSSL's uninstrumented d2i_OCSP_REQUEST. The
 * included pxyconn.c IS SanCov-instrumented (-print_coverage=1 lists
 * pxy_http_reqhdr_filter_line, pxy_http_resphdr_filter_line and
 * pxy_ocsp_is_valid_uri as COVERED_FUNC). In the image, libFuzzer with
 * -fork=2 -ignore_crashes=1 stops at cov: 111 after ~60 s and stays there through
 * 16M execs. Plain runs stop within seconds on the upstream url_dec
 * heap-buffer-overflow, so a time-boxed run that keeps restarting on that crash
 * (Mayhem's 300 s run: 89) can finish below the plateau.
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

static void
http_ctx_clear(pxy_conn_ctx_t *ctx)
{
	free(ctx->http_method);
	free(ctx->http_uri);
	free(ctx->http_host);
	free(ctx->http_content_type);
	free(ctx->http_status_code);
	free(ctx->http_status_text);
	free(ctx->http_content_length);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	pxy_conn_ctx_t *ctx;
	struct evbuffer *in;
	char *line, *replace;

	ctx = calloc(1, sizeof(*ctx));
	in = evbuffer_new();
	if (!ctx || !in || evbuffer_add(in, data, size) == -1)
		abort();

	/* request header, as the src.bev branch of pxy_bev_readcb() */
	while (!ctx->seen_req_header &&
	       (line = evbuffer_readln(in, NULL, EVBUFFER_EOL_CRLF))) {
		replace = pxy_http_reqhdr_filter_line(line, ctx);
		if (replace != line)
			free(line);
		free(replace);
	}
	/* request header complete: the OCSP check of pxy_ocsp_deny() */
	if (ctx->seen_req_header && !ctx->enomem && ctx->http_method &&
	    ctx->http_uri && !strncasecmp(ctx->http_method, "GET", 3))
		(void)pxy_ocsp_is_valid_uri(ctx->http_uri, ctx);

	/* response header, as the dst.bev branch of pxy_bev_readcb() */
	while (!ctx->seen_resp_header && !ctx->enomem &&
	       (line = evbuffer_readln(in, NULL, EVBUFFER_EOL_CRLF))) {
		replace = pxy_http_resphdr_filter_line(line, ctx);
		if (replace != line)
			free(replace);
		free(line);
	}

	http_ctx_clear(ctx);
	free(ctx);
	evbuffer_free(in);
	return 0;
}
