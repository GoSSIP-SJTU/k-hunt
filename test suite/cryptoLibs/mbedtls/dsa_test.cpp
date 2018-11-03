#include <mbedtls\ecdsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int arc, char **arv, char **envc)
{
	char *plainText = (char *)malloc(5000);
	char *cipherText = (char *)malloc(5000);
	memset(plainText, 0, 5000);
	memset(cipherText, 0, 5000);
	size_t len;
	strcat(plainText, "hello world!hello world!hello world!");
	mbedtls_ecdsa_context ctx; 
	mbedtls_ecdsa_init(&ctx);
	mbedtls_ecdsa_genkey(&ctx, MBEDTLS_ECP_DP_SECP256R1, NULL, NULL);
	mbedtls_ecdsa_write_signature(&ctx, MBEDTLS_MD_SHA1,(unsigned char *)plainText, strlen(plainText),(unsigned char *) cipherText, &len, NULL, NULL);
	int a = mbedtls_ecdsa_read_signature(&ctx, (unsigned char *)plainText, strlen(plainText), (unsigned char *)cipherText, len);
	return 1;
}