
#include <mbedtls\aes.h>
#include <stdio.h>
#include <string.h>
int main()
{
	uint32_t key[] = { 0x12345678, 0x12345678, 0x12345678, 0x12345678};
	char plainText[] = "1234567812345678";
	char cipherText[17];
	char decryptText[17];
	memset(cipherText, 0, 17);
	memset(decryptText, 0, 17);
	mbedtls_aes_context ctx;
	mbedtls_aes_init(&ctx);
	printf("plainText:%s\n", plainText);
	mbedtls_aes_setkey_enc(&ctx,( unsigned char *) key, 128);
	mbedtls_aes_encrypt(&ctx, (unsigned char *)plainText, (unsigned char *)cipherText);
	printf("encrypt Text:%s\n", cipherText);
	mbedtls_aes_setkey_dec(&ctx, (unsigned char *)key, 128);
	mbedtls_aes_decrypt(&ctx, (unsigned char *)cipherText, (unsigned char *)decryptText);
	printf("decrypt Text:%s\n",decryptText);
	mbedtls_aes_free(&ctx);
	return 1;
}