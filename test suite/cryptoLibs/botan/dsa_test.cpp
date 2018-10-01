#include "build.h"
#include <botan\dsa.h>
#include <botan/auto_rng.h>
using namespace Botan;
int main()
{
	char *plainText = (char *)malloc(5000);
	char *cipherText = (char *)malloc(5000);
	memset(plainText, 0, 5000);
	memset(cipherText, 0, 5000);
	AutoSeeded_RNG rng;
	DL_Group dlgroup(rng, DL_Group::Prime_Subgroup, 1024);
	DSA_PrivateKey privatekey(rng, dlgroup);
	strcat(plainText, "hello world!");
	DSA_Signature_Operation signop(privatekey);
	DSA_Verification_Operation  verifyop(privatekey);
	SecureVector<byte> out = signop.sign((byte *)plainText, strlen(plainText), rng);
	int i = 0;
	for (byte* it = out.begin(); it != out.end(); it++)
	{
		printf("%x", *it);
		cipherText[i++] = *it;
	}
	printf("\n");
	bool out1 = verifyop.verify((byte*)plainText, strlen(plainText), (byte *)cipherText, i);
	if (out1)
		printf("ok!");
	else
		printf("wrong!");
	free(plainText);
	free(cipherText);
	return 1;
}