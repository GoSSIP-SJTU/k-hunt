#include<stdio.h>

#include<gcrypt.h>


// Output data in bytes
void output(uint8_t *data, size_t len)
{
	for (size_t i = 0; i < len; ++i)
	{
		printf("0x%02x, ", data[i]);
		if ((i + 1) % 10 == 0)
		{
			puts("");
		}
	}
	puts("");
}


void check(int algo,
	const void *kek, size_t keklen,
	const void *data, size_t datalen,
	const void *expected, size_t expectedlen)
{
	gcry_error_t err;
	gcry_cipher_hd_t hd;
	unsigned char outbuf[32 + 8];
	size_t outbuflen;

	err = gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_AESWRAP, 0);
	if (err)
	{
		printf("gcry_cipher_open failed: %s\n", gpg_strerror(err));
		return;
	}

	err = gcry_cipher_setkey(hd, kek, keklen);
	if (err)
	{
		printf("gcry_cipher_setkey failed: %s\n", gpg_strerror(err));
		return;
	}

	outbuflen = datalen + 8;
	if (outbuflen > sizeof(outbuf))
		err = gpg_error(GPG_ERR_INTERNAL);
	else
		err = gcry_cipher_encrypt(hd, outbuf, outbuflen, data, datalen);
	if (err)
	{
		printf("gcry_cipher_encrypt failed: %s\n", gpg_strerror(err));
		return;
	}

	puts("Plaintext:");
	output((uint8_t*)data, datalen);
	puts("");

	puts("Ciphertext:[Encrypted]");
	output(outbuf, outbuflen);
	puts("");

	if (outbuflen != expectedlen || memcmp(outbuf, expected, expectedlen))
	{
		const unsigned char *s;
		int i;

		printf("mismatch at encryption!\n");
		fprintf(stderr, "computed: ");
		for (i = 0; i < outbuflen; i++)
			fprintf(stderr, "%02x ", outbuf[i]);
		fprintf(stderr, "\nexpected: ");
		for (s = (const unsigned char *)expected, i = 0; i < expectedlen; s++, i++)
			fprintf(stderr, "%02x ", *s);
		putc('\n', stderr);
	}


	outbuflen = expectedlen - 8;
	if (outbuflen > sizeof(outbuf))
		err = gpg_error(GPG_ERR_INTERNAL);
	else
		err = gcry_cipher_decrypt(hd, outbuf, outbuflen, expected, expectedlen);
	if (err)
	{
		printf("gcry_cipher_decrypt failed: %s\n", gpg_strerror(err));
		return;
	}

	puts("Plaintext:[Decrypted]");
	output(outbuf, outbuflen);
	puts("");

	if (outbuflen != datalen || memcmp(outbuf, data, datalen))
	{
		const unsigned char *s;
		int i;

		printf("mismatch at decryption!\n");
		fprintf(stderr, "computed: ");
		for (i = 0; i < outbuflen; i++)
			fprintf(stderr, "%02x ", outbuf[i]);
		fprintf(stderr, "\nexpected: ");
		for (s = (const unsigned char *)data, i = 0; i < datalen; s++, i++)
			fprintf(stderr, "%02x ", *s);
		putc('\n', stderr);
	}

	/* Now the last step again with a key reset. */
	gcry_cipher_reset(hd);

	outbuflen = expectedlen - 8;
	if (outbuflen > sizeof(outbuf))
		err = gpg_error(GPG_ERR_INTERNAL);
	else
		err = gcry_cipher_decrypt(hd, outbuf, outbuflen, expected, expectedlen);
	if (err)
	{
		printf("gcry_cipher_decrypt(2) failed: %s\n", gpg_strerror(err));
		return;
	}

	if (outbuflen != datalen || memcmp(outbuf, data, datalen))
		printf("mismatch at decryption(2)!\n");

	/* And once ore without a key reset. */
	outbuflen = expectedlen - 8;
	if (outbuflen > sizeof(outbuf))
		err = gpg_error(GPG_ERR_INTERNAL);
	else
		err = gcry_cipher_decrypt(hd, outbuf, outbuflen, expected, expectedlen);
	if (err)
	{
		printf("gcry_cipher_decrypt(3) failed: %s\n", gpg_strerror(err));
		return;
	}

	if (outbuflen != datalen || memcmp(outbuf, data, datalen))
		printf("mismatch at decryption(3)!\n");

	gcry_cipher_close(hd);
}


void test_aes()
{
	check(GCRY_CIPHER_AES128,
			"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F", 16,
			"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF", 16,
			"\x1F\xA6\x8B\x0A\x81\x12\xB4\x47\xAE\xF3\x4B\xD8\xFB\x5A\x7B\x82"
			"\x9D\x3E\x86\x23\x71\xD2\xCF\xE5", 24);
}

int main()
{
	puts("AES test:\n");
	test_aes();
	return 0;
}