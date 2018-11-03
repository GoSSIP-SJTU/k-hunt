#include <cstdio>
#include <string>
#include <windows.h>
#include <nettle\rsa.h>
#include <nettle\yarrow.h>
#include <nettle\gmp.h>
#include <stdio.h>
#include <stdlib.h>

using namespace std;

int main(int argc, char *argv[]){
	FILE *file = fopen(argv[1], "r");
	fseek(file, 0L, SEEK_END);
	int flen = ftell(file);
	char init_data[2048] = { 0 };
	fseek(file, 0L, SEEK_SET);
	fread(init_data, flen, 1, file);
	init_data[flen] = 0;
	printf("init_data\n%s\n\n", init_data);

	char decrypted[4096] = { 0 };
	mpz_t encrypted;
	char seed[256] = "ABCDEFGH12345678ABCDEFGH1234567890";
	char rand[256] = { 0 };
	rsa_private_key privateKey;
	rsa_public_key publicKey;
	yarrow256_ctx ctx;

	memset(decrypted, 0, sizeof(decrypted));
	rsa_private_key_init(&privateKey);
	rsa_public_key_init(&publicKey);
	mpz_init2(encrypted, 4096);
	//mpz_init2(decrypted, 4096);

	yarrow256_init(&ctx, 0, NULL);
	yarrow256_seed(&ctx, 256, (uint8_t *)seed);
	//yarrow256_random(&ctx, sizeof(rand), (uint8_t *)rand);

	int ret = rsa_generate_keypair(&publicKey, &privateKey, (void *)&ctx, (nettle_random_func *)yarrow256_random, NULL, NULL, 2048, 256);
	if (ret == 0){
		printf("rsa_generate_keypair error!\n");
		return -1;
	}

	//encrypted
	ret = rsa_encrypt(&publicKey, &ctx, (nettle_random_func *)yarrow256_random, flen, (uint8_t *)init_data, encrypted);
	if (ret == 0){
		printf("rsa_encrypt error!\n");
		return -1;
	}

	char edata[4096] = { 0 };
	mpz_get_str(edata, 16, encrypted);

	file = fopen(argv[1], "wb");
	fwrite(edata, 1, encrypted->_mp_alloc * 4, file);
	fclose(file);
	printf("encrypted\nlength: %d\n%s\n\n", encrypted->_mp_alloc, edata);
	//printf("%d\n", encrypted->_mp_size);

	//Ω‚√‹
	file = fopen(argv[1], "rb");
	fseek(file, 0L, SEEK_END);
	flen = ftell(file);
	memset(init_data, 0, sizeof(init_data));
	fseek(file, 0L, SEEK_SET);
	fread(init_data, flen, 1, file);
	init_data[flen] = 0;
	fclose(file);
	printf("encrypted_data\nlength: %d\n%s\n\n", flen, init_data);

	mpz_t data;
	mpz_init2(data, flen);
	//ret = mpz_set_str(data, init_data, 16);
	ret=mpz_init_set_str(data, init_data, 16);
	if (ret == -1){
		printf("mpz_set_str error!\n");
		return -1;
	}

	int len = sizeof(decrypted);
	ret = rsa_decrypt(&privateKey, (size_t *)&len, (uint8_t *)decrypted, data);
	if (ret == 0){
		printf("rsa_decrypt error!\n");
		return -1;
	}

	file = fopen(argv[1], "wb");
	fwrite(decrypted, 1, len, file);
	fclose(file);
	printf("decrypted\nlength: %d\n%s\n\n", len, decrypted);

	mpz_clear(encrypted);
	mpz_clear(data);
	return 0;
}