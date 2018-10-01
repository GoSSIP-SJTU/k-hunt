#include "build.h"
#include <botan\ecdsa.h>
#include <stdio.h>
#include <string>
#include <botan/auto_rng.h>
#include <botan/ecdsa.h>
#include <botan/ec_group.h>
#include <botan/pubkey.h>
#include <botan/hex.h>
#include <iostream>
using namespace std;
using namespace Botan;
int main()
{
	char *plainText = (char *)malloc(5000);
	char *cipherText = (char *)malloc(5000);
	memset(plainText, 0, 5000);
	memset(cipherText, 0, 5000);
	Botan::AutoSeeded_RNG rng;
	// Generate ECDSA keypair
	EC_Group g(string("secp256r1"));
	ECDSA_PrivateKey privatekey(rng, g);
	strcat(plainText, "hello world!hello world!hello world!");
	ECDSA_Signature_Operation privateop(privatekey);
	ECDSA_Verification_Operation  publicop(privatekey);
	SecureVector<byte> out = privateop.sign((byte *)plainText, strlen(plainText), rng);
	int i = 0;
	for (byte* it = out.begin(); it != out.end(); it++)
	{
		printf("%x", *it);
		cipherText[i++] = *it;
	}
	printf("\n");
	SecureVector<byte> out1 = publicop.verify((byte*)plainText, strlen(plainText), (byte *)cipherText, i);;
	i = 0;
	memset(cipherText, 0, 5000);
	for (byte* it = out1.begin(); it != out1.end(); it++)
	{
		printf("%x", *it);
		cipherText[i++] = *it;
	}
	printf("%s", cipherText);
	return 1;

}