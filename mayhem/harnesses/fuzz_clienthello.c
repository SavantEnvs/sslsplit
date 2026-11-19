/*
 * Fuzz sslsplit's SSLv2/SSLv3/TLS ClientHello parser, ssl_tls_clienthello_parse()
 * (ssl.c). The proxy calls it on the first bytes a client sends (up to 4096 peeked
 * bytes, pxyconn.c) to find the ClientHello and extract the SNI server name.
 *
 * Input: byte 0 bit 0 selects the `search` mode (0 = record must start at the
 * buffer, as the proxy calls it; 1 = scan for a ClientHello anywhere in the
 * buffer); the rest is the client's bytes. No state is kept across inputs.
 */
#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ssl.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const unsigned char *chello = NULL;
	char *sni = NULL;
	unsigned char *buf;
	int search, rv;

	if (size < 1)
		return 0;
	search = data[0] & 1;
	/* exact-size heap copy so ASan sees any overread past the client bytes */
	buf = malloc(size - 1 ? size - 1 : 1);
	if (!buf)
		return 0;
	memcpy(buf, data + 1, size - 1);
	rv = ssl_tls_clienthello_parse(buf, (ssize_t)(size - 1), search,
	                               &chello, &sni);
	if (rv == 0 && chello) {
		/* the returned pointer must lie inside the input buffer */
		if (chello < buf || chello >= buf + (size - 1))
			abort();
	}
	if (sni) {
		/* a found server name must be a NUL-terminated string */
		volatile size_t n = strlen(sni);
		(void)n;
		free(sni);
	}
	free(buf);
	return 0;
}
