#include <eccrypto.h>
#include <osrng.h>
#include <oids.h>
#include <stdio.h>
#include <stdlib.h>

using namespace CryptoPP;
using namespace std;

int main(int argc, char *argv[]){
	FILE *file = fopen(argv[1], "r");
	fseek(file, 0L, SEEK_END);
	int flen = ftell(file);
	char * init_data = (char *)malloc(flen + 1);
	if (init_data == NULL){
		fclose(file);
		return 0;
	}
	fseek(file, 0L, SEEK_SET);
	fread(init_data, flen, 1, file);
	init_data[flen] = 0;
	printf("init_data\n%s\n\n", init_data);

	//密钥生成
	AutoSeededRandomPool rng;

	ECDSA<ECP, SHA1>::PrivateKey privateKey;
	//privateKey.GenerateRandomWithKeySize(rng, 1024);
	ECDSA<ECP, SHA1>::PublicKey publicKey;
	//publicKey.AssignFrom(privateKey);

	privateKey.Initialize(rng, ASN1::secp160r1());
	bool res = privateKey.Validate(rng, 3);
	if (!res)
	{
		printf("privateKey error!\n");
		return 0;
	}
	privateKey.MakePublicKey(publicKey);

	//签名
	string sign;
	ECDSA<ECP, SHA1>::Signer signer(privateKey);
	StringSource ss1(init_data, true, new SignerFilter(rng, signer, new StringSink(sign)));

	//验证
	//sign[0] = 'a';
	ECDSA<ECP, SHA1>::Verifier verifier(publicKey);
	StringSource ss2(init_data + sign, true, new SignatureVerificationFilter(verifier, NULL, SignatureVerificationFilter::THROW_EXCEPTION));
	//StringSource ss2(init_data + sign, true, new SignatureVerificationFilter(verifier, new ArraySink((byte*)&result, sizeof(result))));

	printf("verify ok!\n");
	return 0;
}