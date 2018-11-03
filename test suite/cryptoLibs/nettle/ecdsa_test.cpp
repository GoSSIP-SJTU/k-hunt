#include <cstdio>
#include <string>
#include <windows.h>
#include <nettle\ecdsa.h>
#include <nettle\sha.h>
#include <nettle\knuth-lfib.h>
#include <nettle\ecc-curve.h>
#include <nettle\ecc.h>
#include <stdio.h>
#include <stdlib.h>

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
	ecc_scalar privateKey;
	ecc_point publicKey;
	dsa_signature sign;
	sha256_ctx sctx;
	knuth_lfib_ctx kctx;

	memset(hdata, 0, sizeof(hdata));

	HMODULE hd = LoadLibraryA("libhogweed-4-2.dll");
	FARPROC curve = GetProcAddress(hd, "nettle_secp_256r1");
	if (curve == 0){
		printf("Load Library Failed!\n");
		exit(0);
	}
	nettle_ecc_point_init(&publicKey, (ecc_curve *)curve);
	nettle_ecc_scalar_init(&privateKey, (ecc_curve *)curve);
	//nettle_ecc_point_init(&publicKey, &nettle_secp_521r1);
	//nettle_ecc_scalar_init(&privateKey, &nettle_secp_521r1);

	sha256_init(&sctx);
	sha256_update(&sctx, flen, (uint8_t *)init_data);
	sha256_digest(&sctx, SHA256_DIGEST_SIZE, (uint8_t *)hdata);

	knuth_lfib_init(&kctx, 1234);
	ecdsa_generate_keypair(&publicKey, &privateKey, &kctx, (nettle_random_func *)knuth_lfib_random);
	
	int len = SHA256_DIGEST_SIZE;
	dsa_signature_init(&sign);
	
	ecdsa_sign(&privateKey,&kctx, (nettle_random_func *)knuth_lfib_random, len, (uint8_t *)hdata, &sign);

	//hdata[0] = 'w';
	int ret = ecdsa_verify(&publicKey, len, (uint8_t *)hdata, &sign);
	if (ret == 0){
		printf("verify error!\n");
	}
	else{
		printf("verify ok!\n");
	}

	ecc_point_clear(&publicKey);
	ecc_scalar_clear(&privateKey);
	dsa_signature_clear(&sign);
	return 0;
}