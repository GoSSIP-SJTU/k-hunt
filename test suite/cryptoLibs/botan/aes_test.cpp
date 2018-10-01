#include "build.h"
#include <botan\aes.h>
#include <stdio.h>
using namespace Botan;
int main()
{
	AES_128 aes;
	char plainText[] = "abcdefghijklmnop";
	char decryptText[50];
	_Uint32t key[] = { 0x12345678, 0x12345678, 0x12345678, 0x12345678 };
	char cipherText[50];
	memset(cipherText, 0, 50);
	memset(decryptText, 0, 50);
	aes.set_key((byte *)key, 16);
	printf("plain Text:%s\n", plainText);
	aes.encrypt_n((byte*)plainText, (byte*)cipherText, 1);
	printf("cipher Text:%s\n", cipherText);
	aes.decrypt_n((byte*)cipherText, (byte*)decryptText, 1);
	printf("decrypted Text:%s\n", decryptText);
	return 1;
}