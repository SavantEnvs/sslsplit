/*
 * Fuzz sslsplit's handling of the certificate an upstream server presents: name
 * extraction (SAN/CN), AIA/OCSP URL extraction, string/fingerprint rendering,
 * hostname/wildcard matching against those names, and forging the replacement
 * leaf certificate the proxy hands to the client (ssl_x509_forge, as pxyconn.c
 * does on every certificate-cache miss and on SNI mismatch).
 *
 * Input: one DER-encoded X.509 certificate. Kept across inputs, read-only: the
 * OpenSSL init, a CA key + self-signed CA certificate and a leaf key, generated
 * once in LLVMFuzzerInitialize (the proxy also loads these once at startup).
 */
#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "ssl.h"

static EVP_PKEY *cakey, *leafkey;
static X509 *cacrt;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	X509_NAME *n;

	(void)argc; (void)argv;
	if (ssl_init() == -1)
		abort();
	cakey = ssl_key_genrsa(1024);
	leafkey = ssl_key_genrsa(1024);
	cacrt = X509_new();
	if (!cakey || !leafkey || !cacrt)
		abort();
	X509_set_version(cacrt, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(cacrt), 1);
	X509_gmtime_adj(X509_getm_notBefore(cacrt), 0);
	X509_gmtime_adj(X509_getm_notAfter(cacrt), 86400L * 365);
	X509_set_pubkey(cacrt, cakey);
	n = X509_get_subject_name(cacrt);
	X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC,
	                           (const unsigned char *)"fuzz CA", -1, -1, 0);
	X509_set_issuer_name(cacrt, n);
	if (!X509_sign(cacrt, cakey, EVP_sha256()))
		abort();
	return 0;
}

static void free_strv(char **v)
{
	if (!v)
		return;
	for (char **p = v; *p; p++)
		free(*p);
	free(v);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const unsigned char *p = data;
	unsigned char fpr[SSL_X509_FPRSZ];
	X509 *crt, *forged;
	char **names, **v, *s;
	size_t cnsz;

	crt = d2i_X509(NULL, &p, (long)size);
	if (!crt)
		return 0;

	s = ssl_x509_subject(crt); free(s);
	s = ssl_x509_subject_cn(crt, &cnsz); free(s);
	s = ssl_x509_names_to_str(crt); free(s);
	s = ssl_x509_to_str(crt); free(s);
	s = ssl_x509_fingerprint(crt, 0); free(s);
	(void)ssl_x509_fingerprint_sha1(crt, fpr);
	free_strv(ssl_x509_aias(crt, NID_ad_OCSP));
	free_strv(ssl_x509_aias(crt, NID_ad_ca_issuers));
	free_strv(ssl_x509_ocsps(crt));
	(void)ssl_x509_is_valid(crt);

	/* hostname matching: each certificate name against every other name, as
	 * the proxy matches a client's SNI against the server certificate */
	names = ssl_x509_names(crt);
	if (names) {
		for (v = names; *v; v++) {
			char *w = ssl_wildcardify(*v);
			free(w);
			(void)ssl_x509_names_match(crt, *v);
			for (char **u = names; *u; u++)
				(void)ssl_dnsname_match(*v, strlen(*v),
				                        *u, strlen(*u));
		}
	}

	forged = ssl_x509_forge(cacrt, cakey, crt, leafkey,
	                        names && names[0] ? names[0] : NULL,
	                        "http://crl.example.com/ca.crl");
	if (forged) {
		s = ssl_x509_names_to_str(forged); free(s);
		X509_free(forged);
	}
	free_strv(names);
	X509_free(crt);
	return 0;
}
