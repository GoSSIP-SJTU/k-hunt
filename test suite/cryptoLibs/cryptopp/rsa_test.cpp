#include <rsa.h>
#include <osrng.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

//using namespace std;
using namespace CryptoPP;

int main(int argc, char *argv[]){
	//密钥生成
	AutoSeededRandomPool rng;
	//RandomNumberGenerator rng;

	RSA::PrivateKey privateKey;
	privateKey.GenerateRandomWithKeySize(rng, 2048);
	RSA::PublicKey publicKey(privateKey);

	RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
	RSAES_OAEP_SHA_Decryptor decryptor(privateKey);

	//加密
	char init_data[2048] = { 0 };
	char encrypted[2048] = { 0 };

	FILE *file = fopen(argv[1], "rb+");
	fseek(file, 0L, SEEK_END);
	int flen = ftell(file);
	fseek(file, 0L, SEEK_SET);
	fread(init_data, flen, 1, file);

	encryptor.Encrypt(rng, (byte *)init_data, flen, (byte *)encrypted);
	int elen = encryptor.CiphertextLength(flen);
	
	fseek(file, 0, SEEK_SET);
	fwrite(encrypted, 1, elen, file);

	//解密
	FILE *file1 = fopen("res.txt", "wb");

	fseek(file, 0, SEEK_END);
	flen = ftell(file);
	fseek(file, 0, SEEK_SET);
	fread(init_data, flen, 1, file);
	
	char decrypted[2048] = { 0 };

	DecodingResult dres = decryptor.Decrypt(rng, (byte *)init_data, flen, (byte *)decrypted);
	int dlen = dres.messageLength;
	fwrite(decrypted, 1, dlen, file1);

	fclose(file);
	fclose(file1);
	return 0;
}
