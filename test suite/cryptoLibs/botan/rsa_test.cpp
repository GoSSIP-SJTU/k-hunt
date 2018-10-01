#include <botan/pkcs8.h>
#include <botan/hex.h>
#include <botan/pk_keys.h>
#include <botan/pubkey.h>
#include <botan/auto_rng.h>
#include <botan/rng.h>
#include <botan\rsa.h>
#include <botan\pem.h>
#include <botan\x509_key.h>
using namespace std;
using namespace Botan;
using namespace X509;

int main(int arc,char **arv,char **envc)
{
	char *plainText = (char *)malloc(5000);
	char *cipherText = (char *)malloc(5000);
	memset(plainText, 0, 5000);
	memset(cipherText, 0, 5000);
	AutoSeeded_RNG rng;
	RSA_PrivateKey privatekey(rng, 1024);
	strcat(plainText, "hello world!hello world!hello world!");
	printf("plainText:%s\n", plainText);
	RSA_Private_Operation privateop(privatekey);
	RSA_Public_Operation  publicop(privatekey);
	SecureVector<byte> out = publicop.encrypt((byte *)plainText, strlen(plainText), rng);
	int i = 0;
	puts("cipher Text:");
	for (byte* it = out.begin(); it != out.end();it++)
	{
		printf("%x", *it);
		cipherText[i++] = *it;
	}
	puts("");
	SecureVector<byte> out1 = privateop.decrypt((byte*)cipherText, i);
	i = 0;
	memset(cipherText, 0, 5000);
	for (byte* it = out1.begin(); it != out1.end(); it++)
	{
		cipherText[i++] = *it;
	}
	printf("decrypt Text:%s", cipherText);
	free(plainText);
	free(cipherText);
	return 1;

}