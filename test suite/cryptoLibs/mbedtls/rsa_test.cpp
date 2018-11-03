#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/bignum.h"
#include "mbedtls/x509.h"
#include "mbedtls/rsa.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define KEY_SIZE 2048
#define EXPONENT 65537
const char *pers = "rsa_genkey";
int main()
{
	char plainText[] = "hello world!hello world!";
	char *cipherText = (char *)malloc(5000);
	char *decryptText = (char *)malloc(5000);
	memset(cipherText, 0, 5000);
	memset(decryptText, 0, 5000);
	int ret;
	size_t outlen;
	mbedtls_rsa_context rsa;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
		(const unsigned char *)pers,
		strlen(pers))) != 0)
	{
		printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
		return 1;
	}
	mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
	if ((ret = mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE,
		EXPONENT)) != 0)
	{
		printf(" failed\n  ! mbedtls_rsa_gen_key returned %d\n\n", ret);
		return 1;
	}
	if ((ret = mbedtls_rsa_pkcs1_encrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg,
		MBEDTLS_RSA_PUBLIC, strlen(plainText),
		(unsigned char *)plainText, (unsigned char*)cipherText)) != 0)
	{
		printf(" failed\n  ! mbedtls_rsa_pkcs1_encrypt returned %d\n\n", ret);
		return 1;
	}
	if ((ret = mbedtls_rsa_pkcs1_decrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg,
		MBEDTLS_RSA_PRIVATE, &outlen, (unsigned char*)cipherText, (unsigned char*)decryptText,
		5000)) != 0)
	{
		printf(" failed\n  ! mbedtls_rsa_pkcs1_decrypt returned %d\n\n", ret);
		return 1;
	}
	printf(decryptText);
	mbedtls_rsa_free(&rsa);
	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	free(cipherText);
	free(decryptText);
	return 1;
}