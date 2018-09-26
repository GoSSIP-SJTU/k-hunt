

// data in  dsa-rfc6979.c

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


static void
show_sexp(gcry_sexp_t a)
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
static void *
data_from_hex(const char *string, size_t *r_length)
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

static void
extract_cmp_data(gcry_sexp_t sexp, const char *name, const char *expected)
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
			"ECDSA, 256 bits (prime field)",
			"(private-key"
		" (ecdsa"
		" (curve \"NIST P-256\")"
		" (q #04"
		"     60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"
		"     7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299#)"
		" (d #C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721#)"
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
			"ECDSA, 256 bits (prime field)",
			"With SHA-256, message = \"sample\"",
		"sha256", "sample",
		"A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60",
		"EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
		"F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"
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

	// Sign data
	err = gcry_pk_sign(&sig, data, seckey);
	if (err)
		puts("signing failed.");
	else
		puts("signing success.");
	puts("");

	// Show signature data
	puts("Signature:");
	show_sexp(sig);
	puts("");

	// Verify signature
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
	puts("ECDSA test:\n");
	test_dsa();
	return 0;
}
