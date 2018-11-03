#include <cstdio>
#include <string>
#include <nettle\dsa.h>
#include <nettle\dsa-compat.h>
#include <nettle\knuth-lfib.h>

using namespace std;

int main(int argc, char *argv[]){
	FILE *file = fopen(argv[1], "r");
	fseek(file, 0L, SEEK_END);
	int flen = ftell(file);
	char init_data[1024] = { 0 };
	fseek(file, 0L, SEEK_SET);
	fread(init_data, flen, 1, file);
	init_data[flen] = 0;
	printf("init_data\n%s\n\n", init_data);

	char hdata[1024] = {};
	dsa_private_key privateKey;
	dsa_public_key publicKey;
	dsa_signature sign;
	sha256_ctx sctx;
	knuth_lfib_ctx kctx;

	memset(hdata, 0, sizeof(hdata));
	dsa_public_key_init(&publicKey);
	dsa_private_key_init(&privateKey);

	sha256_init(&sctx);
	sha256_update(&sctx, flen, (uint8_t *)init_data);
	sha256_digest(&sctx, SHA256_DIGEST_SIZE, (uint8_t *)hdata);

	knuth_lfib_init(&kctx, 1234);
	int ret = dsa_generate_keypair(&publicKey, &privateKey, &kctx, (nettle_random_func *)knuth_lfib_random, NULL, NULL, DSA_SHA256_MIN_P_BITS, DSA_SHA1_Q_BITS);
	if (ret == 0){
		printf("dsa_generate_keypair error!\n");
		return -1;
	}

	int len = SHA256_DIGEST_SIZE;
	dsa_signature_init(&sign);
	ret = dsa_sign((dsa_params *)&publicKey, privateKey.x, &kctx, (nettle_random_func *)knuth_lfib_random, len, (uint8_t *)hdata, &sign);
	if (ret == 0){
		printf("dsa_sign error!\n");
		return -1;
	}

	//hdata[0] = 'w';
	ret = dsa_verify((dsa_params *)&publicKey, publicKey.y, len, (uint8_t *)hdata, &sign);
	if (ret == 0){
		printf("verify error!\n");
	}
	else{
		printf("verify ok!\n");
	}

	dsa_private_key_clear(&privateKey);
	dsa_public_key_clear(&publicKey);
	dsa_signature_clear(&sign);
	return 0;
}