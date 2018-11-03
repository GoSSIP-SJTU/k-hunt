
#include<stdio.h>
#include<gcrypt.h>



/* Sample RSA keys, taken from basic.c.  */
static const char sample_private_key_1[] =
"(private-key\n"
" (openpgp-rsa\n"
"  (n #00e0ce96f90b6c9e02f3922beada93fe50a875eac6bcc18bb9a9cf2e84965caa"
"2d1ff95a7f542465c6c0c19d276e4526ce048868a7a914fd343cc3a87dd74291"
"ffc565506d5bbb25cbac6a0e2dd1f8bcaab0d4a29c2f37c950f363484bf269f7"
"891440464baf79827e03a36e70b814938eebdc63e964247be75dc58b014b7ea251#)\n"
"  (e #010001#)\n"
"  (d #046129F2489D71579BE0A75FE029BD6CDB574EBF57EA8A5B0FDA942CAB943B11"
"7D7BB95E5D28875E0F9FC5FCC06A72F6D502464DABDED78EF6B716177B83D5BD"
"C543DC5D3FED932E59F5897E92E6F58A0F33424106A3B6FA2CBF877510E4AC21"
"C3EE47851E97D12996222AC3566D4CCB0B83D164074ABF7DE655FC2446DA1781#)\n"
"  (p #00e861b700e17e8afe6837e7512e35b6ca11d0ae47d8b85161c67baf64377213"
"fe52d772f2035b3ca830af41d8a4120e1c1c70d12cc22f00d28d31dd48a8d424f1#)\n"
"  (q #00f7a7ca5367c661f8e62df34f0d05c10c88e5492348dd7bddc942c9a8f369f9"
"35a07785d2db805215ed786e4285df1658eed3ce84f469b81b50d358407b4ad361#)\n"
"  (u #304559a9ead56d2309d203811a641bb1a09626bc8eb36fffa23c968ec5bd891e"
"ebbafc73ae666e01ba7c8990bae06cc2bbe10b75e69fcacb353a6473079d8e9b#)\n"
" )\n"
")\n";

static const char sample_public_key_1[] =
"(public-key\n"
" (rsa\n"
"  (n #00e0ce96f90b6c9e02f3922beada93fe50a875eac6bcc18bb9a9cf2e84965caa"
"2d1ff95a7f542465c6c0c19d276e4526ce048868a7a914fd343cc3a87dd74291"
"ffc565506d5bbb25cbac6a0e2dd1f8bcaab0d4a29c2f37c950f363484bf269f7"
"891440464baf79827e03a36e70b814938eebdc63e964247be75dc58b014b7ea251#)\n"
"  (e #010001#)\n"
" )\n"
")\n";

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


static void
check_keys_crypt(gcry_sexp_t pkey, gcry_sexp_t skey, gcry_sexp_t plain0)
{
	gcry_sexp_t plain1, cipher, l;
	gcry_mpi_t x0, x1;
	int rc;
	int have_flags;

	/* Extract data from plaintext.  */
	l = gcry_sexp_find_token(plain0, "value", 0);
	x0 = gcry_sexp_nth_mpi(l, 1, GCRYMPI_FMT_USG);
	gcry_sexp_release(l);

	/* Encrypt data.  */
	rc = gcry_pk_encrypt(&cipher, plain0, pkey);
	if (rc)
		puts("encryption failed.\n");
	else
		puts("encryption success.\n");

	show_sexp(cipher);

	l = gcry_sexp_find_token(cipher, "flags", 0);
	have_flags = !!l;
	gcry_sexp_release(l);

	/* Decrypt data.  */
	rc = gcry_pk_decrypt(&plain1, cipher, skey);
	if (rc)
		puts("decryption failed.\n");
	else
		puts("decryption success.\n");

	/* Extract decrypted data.  Note that for compatibility reasons, the
	output of gcry_pk_decrypt depends on whether a flags lists (even
	if empty) occurs in its input data.  Because we passed the output
	of encrypt directly to decrypt, such a flag value won't be there
	as of today.  We check it anyway. */
	l = gcry_sexp_find_token(plain1, "value", 0);
	if (l)
	{
		if (!have_flags)
			puts("compatibility mode of pk_decrypt broken.");
		gcry_sexp_release(plain1);
		x1 = gcry_sexp_nth_mpi(l, 1, GCRYMPI_FMT_USG);
		gcry_sexp_release(l);
	}
	else
	{
		if (have_flags)
			puts("compatibility mode of pk_decrypt broken.");
		x1 = gcry_sexp_nth_mpi(plain1, 0, GCRYMPI_FMT_USG);
		gcry_sexp_release(plain1);
	}

	/* Compare.  */
	if (gcry_mpi_cmp(x0, x1))
		puts("data corrupted.");

}

void check_keys(gcry_sexp_t pkey, gcry_sexp_t skey, unsigned int nbits_data)
{
	gcry_sexp_t plain;
	gcry_mpi_t x;
	int rc;

	/* Create plain text.  */
	//x = gcry_mpi_new(nbits_data);
	//gcry_mpi_randomize(x, nbits_data, GCRY_WEAK_RANDOM);  // This step will be fail in my computer,
	//rc = gcry_sexp_build(&plain, NULL, "(data (flags raw) (value %m))", x);
	rc = gcry_sexp_build(&plain, NULL, "(data (flags raw) (value %s))", "This is a test data.");
	if (rc)
		printf("converting data for encryption failed: %s\n", gcry_strerror(rc));

	check_keys_crypt(pkey, skey, plain);
	gcry_sexp_release(plain);

}


// Get key pair 
void get_keys_sample(gcry_sexp_t *pkey, gcry_sexp_t *skey)
{
	gcry_sexp_t pub_key, sec_key;
	int rc;

	rc = gcry_sexp_sscan(&pub_key, NULL, sample_public_key_1, strlen(sample_public_key_1));
	if (!rc)
		rc = gcry_sexp_sscan(&sec_key, NULL, sample_private_key_1, strlen(sample_private_key_1));
	if (rc)
		printf("converting sample keys failed: %s\n", gcry_strerror(rc));

	*pkey = pub_key;
	*skey = sec_key;
}

void test_rsa()
{
	gpg_error_t err;
	gcry_sexp_t pkey, skey;

	get_keys_sample(&pkey, &skey);
	check_keys(pkey, skey, 800);

	// Release resource
	gcry_sexp_release(pkey);
	gcry_sexp_release(skey);
}

int main()
{
	puts("RSA test:\n");
	test_rsa();
	return 0;
}