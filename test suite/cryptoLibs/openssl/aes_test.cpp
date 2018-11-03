#include <stdio.h>  
#include <string.h>  
#include <openssl/aes.h>  
#include <openssl/rand.h>  

/* file testaes.cpp */

static void hexdump(
	FILE *f,
	const char *title,
	const unsigned char *s,
	int l)
{
	int n = 0;

	fprintf(f, "%s", title);
	for (; n < l; ++n) {
		if ((n % 16) == 0) {
			fprintf(f, "\n%04x", n);
		}
		fprintf(f, " %02x", s[n]);
	}

	fprintf(f, "\n");
}

int main(int argc, char **argv)
{
	//128bits key.  
	unsigned char   rkey[16];
	//Internal key.  
	AES_KEY         key;

	//Testdata.  
	// [yasi] Make static content instead of random text  
	unsigned char   plaintext[AES_BLOCK_SIZE * 4] =
	{
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'i', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'i',
		'0', '1', '2', '3', '4', '5', '6', '7', '0', '1', '2', '3', '4', '5', '6', '7',
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'i', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'i',
		'0', '1', '2', '3', '4', '5', '6', '7', '0', '1', '2', '3', '4', '5', '6', '7'
	};
	unsigned char   ciphertext[AES_BLOCK_SIZE * 4];
	unsigned char   checktext[AES_BLOCK_SIZE * 4];

	//Init vector.  
	unsigned char   iv[AES_BLOCK_SIZE * 4];
	//Save vector.  
	unsigned char   saved_iv[AES_BLOCK_SIZE * 4];

	int nr_of_bits = 0;
	int nr_of_bytes = 0;

	//Zeror buffer.  
	memset(ciphertext, 0, sizeof ciphertext);
	memset(checktext, 0, sizeof checktext);

	//Generate random  
	RAND_pseudo_bytes(rkey, sizeof rkey);
	RAND_pseudo_bytes(saved_iv, sizeof saved_iv);

	hexdump(stdout, "== rkey ==",
		rkey,
		sizeof(rkey));
	hexdump(stdout, "== iv ==",
		saved_iv,
		sizeof(saved_iv));
	printf("\n");

	hexdump(stdout, "== plaintext ==",
		plaintext,
		sizeof(plaintext));
	printf("\n");

	//Entrypt  
	memcpy(iv, saved_iv, sizeof(iv));
	nr_of_bits = 8 * sizeof(rkey);
	AES_set_encrypt_key(rkey, nr_of_bits, &key);
	nr_of_bytes = sizeof(plaintext);
	AES_cbc_encrypt(plaintext,
		ciphertext,
		nr_of_bytes,
		&key,
		iv,
		AES_ENCRYPT);

	hexdump(stdout, "== ciphertext ==",
		ciphertext,
		sizeof(ciphertext));
	printf("\n");
	// [yasi] iv is changed in encryption  
	hexdump(stdout, "== iv changed ==",
		iv,
		sizeof(iv));
	printf("\n");

	//Decrypt  
	memcpy(iv, saved_iv, sizeof(iv));       // [yasi] without this line, decrypt will fail because iv is changed in encryption  
	nr_of_bits = 8 * sizeof(rkey);
	AES_set_decrypt_key(rkey, nr_of_bits, &key);
	nr_of_bytes = sizeof(ciphertext);

	AES_cbc_encrypt(ciphertext,
		checktext,
		nr_of_bytes,
		&key, iv,
		AES_DECRYPT);
	hexdump(stdout, "== checktext ==",
		checktext,
		sizeof(checktext));
	printf("\n");

	return 0;
}