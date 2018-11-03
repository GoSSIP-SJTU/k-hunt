#include <dsa.h>
#include <osrng.h>
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

	AutoSeededRandomPool rng;
	DSA::PrivateKey privateKey;
	privateKey.GenerateRandomWithKeySize(rng, 1024);
	DSA::PublicKey publicKey;
	publicKey.AssignFrom(privateKey);

	string sign;
	DSA::Signer signer(privateKey);
	StringSource ss1(init_data, true, new SignerFilter(rng, signer, new StringSink(sign)));

	//sign[0] = 'a';
	DSA::Verifier verifier(publicKey);
	StringSource ss2(init_data + sign, true, new SignatureVerificationFilter(verifier, NULL, SignatureVerificationFilter::THROW_EXCEPTION));

	printf("verify ok!\n");

	return 0;
}