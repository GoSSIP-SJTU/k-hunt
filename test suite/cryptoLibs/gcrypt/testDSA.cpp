
// data in dsa-rfc6979.c

#include<stdio.h>
#include<gcrypt.h>


/* The atoi macros assume that the buffer has only valid digits.  */
#define atoi_1(p)   (*(p) - '0' )
#define xtoi_1(p)   (*(p) <= '9'? (*(p)- '0'): \
                     *(p) <= 'F'? (*(p)-'A'+10):(*(p)-'a'+10))
#define xtoi_2(p)   ((xtoi_1(p) * 16) + xtoi_1((p)+1))

/* Digit predicates.  */
#define digitp(p)   (*(p) >= '0' && *(p) <= '9')
#define hexdigitp(a) (digitp (a)                     \
                      || (*(a) >= 'A' && *(a) <= 'F')  \
                      || (*(a) >= 'a' && *(a) <= 'f'))


void show_sexp(gcry_sexp_t a)
{
	char *buf;
	size_t size;

	size = gcry_sexp_sprint(a, GCRYSEXP_FMT_ADVANCED, NULL, 0);
	buf = (char *)gcry_xmalloc(size);

	gcry_sexp_sprint(a, GCRYSEXP_FMT_ADVANCED, buf, size);
	fprintf(stdout, "%.*s", (int)size, buf);
	gcry_free(buf);
}


/* Convert STRING consisting of hex characters into its binary
representation and return it as an allocated buffer. The valid
length of the buffer is returned at R_LENGTH.  The string is
delimited by end of string.  The function returns NULL on
error.  */
void * data_from_hex(const char *string, size_t *r_length)
{
	const char *s;
	unsigned char *buffer;
	size_t length;

	buffer = (unsigned char *)gcry_xmalloc(strlen(string) / 2 + 1);
	length = 0;
	for (s = string; *s; s += 2)
	{
		if (!hexdigitp(s) || !hexdigitp(s + 1))
			printf("error parsing hex string `%s'\n", string);
		((unsigned char*)buffer)[length++] = xtoi_2(s);
	}
	*r_length = length;
	return buffer;
}

void extract_cmp_data(gcry_sexp_t sexp, const char *name, const char *expected)
{
	gcry_sexp_t l1;
	const void *a;
	size_t alen;
	void *b;
	size_t blen;

	l1 = gcry_sexp_find_token(sexp, name, 0);
	a = gcry_sexp_nth_data(l1, 1, &alen);
	b = data_from_hex(expected, &blen);
	if (!a)
		printf("parameter \"%s\" missing in key\n", name);
	else if (alen != blen || memcmp(a, b, alen))
	{
		printf("parameter \"%s\" does not match expected value\n", name);
	}
	gcry_free(b);
	gcry_sexp_release(l1);
}

void test_dsa()
{
	gpg_error_t err;
	int tno, i, hashalgo;
	gcry_sexp_t seckey, data, sig;
	unsigned char digest[64];
	int digestlen;

	struct {
		const char *name;
		const char *key;
	} keys[] = {
		{
			"DSA, 1024 bits",
			"(private-key"
		" (DSA"
		" (p #86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447"
		"     E6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED88"
		"     73ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C"
		"     881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779#)"
		" (q #996F967F6C8E388D9E28D01E205FBA957A5698B1#)"
		" (g #07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D"
		"     89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD"
		"     87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA4"
		"     17BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD#)"
		" (x #411602CB19A6CCC34494D79D98EF1E7ED5AF25F7#)"
		" (y #5DF5E01DED31D0297E274E1691C192FE5868FEF9E19A84776454B100CF16F653"
		"     92195A38B90523E2542EE61871C0440CB87C322FC4B4D2EC5E1E7EC766E1BE8D"
		"     4CE935437DC11C3C8FD426338933EBFE739CB3465F4D3668C5E473508253B1E6"
		"     82F65CBDC4FAE93C2EA212390E54905A86E2223170B44EAA7DA5DD9FFCFB7F3B#)"
		" ))"
		},
		{ NULL }
	};

	static struct {
		const char *keyname;
		const char *name;
		const char *hashname;
		const char *message;
		const char *k, *r, *s;
	} tests[] = {
		{
			"DSA, 1024 bits",
			"With SHA-1, message = \"sample\"",
		"sha1", "sample",
		"7BDB6B0FF756E1BB5D53583EF979082F9AD5BD5B",
		"2E1A0C2562B2912CAAF89186FB0F42001585DA55",
		"29EFB6B0AFF2D7A68EB70CA313022253B9A88DF5"
		},
		{ NULL }
	};

	i = 0;
	tno = 0;
	err = gcry_sexp_new(&seckey, keys[i].key, 0, 1);
	if (err)
		puts("reading key failed.");

	hashalgo = gcry_md_map_name(tests[tno].hashname);
	if (!hashalgo)
		printf("hash with name '%s' is not supported\n", tests[tno].hashname);

	digestlen = gcry_md_get_algo_dlen(hashalgo);
	if (digestlen > sizeof(digest))
		puts("internal error: digest does not fit into our buffer\n");

	gcry_md_hash_buffer(hashalgo, digest,
		tests[tno].message, strlen(tests[tno].message));

	err = gcry_sexp_build(&data, NULL,
		"(data "
		" (flags rfc6979)"
		" (hash %s %b))",
		tests[tno].hashname, digestlen, digest);
	if (err)
		puts("building data sexp failed.");

	err = gcry_pk_sign(&sig, data, seckey);
	if (err)
		puts("signing failed.");
	else
		puts("signing success.");
	puts("");

	puts("Signature:");
	show_sexp(sig);
	puts("");

	extract_cmp_data(sig, "r", tests[tno].r);
	extract_cmp_data(sig, "s", tests[tno].s);

	err = gcry_pk_verify(sig, data, seckey);
	if (err)
		puts("verification failed.");
	else
		puts("verification success.");
	puts("");

	// Release resourse
	gcry_sexp_release(sig);
	gcry_sexp_release(data);
	gcry_sexp_release(seckey);
}

int main()
{
	puts("DSA test:\n");
	test_dsa();
	return 0;
}
