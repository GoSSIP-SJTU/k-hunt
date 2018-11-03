#include <cstdio>
#include <string>
#include <nettle\aes.h>
#include <nettle\yarrow.h>
#include <nettle\cbc.h>
#include <stdio.h>
#include <stdlib.h>

using namespace std;

int main(int argc, char *argv[]){
	//密钥生成
	aes256_ctx aes;
	char key[32] = { 0 };
	memcpy(key, "abcdefgh12345678opqrstuv98765432", sizeof(key));
	aes256_set_encrypt_key(&aes, (uint8_t *)key);
	
	char seed[256] = "abcdefgh12345678zxcvbnml987654321qazwsxedcrfvtgbyhnujmikolp";
	char iv[AES_BLOCK_SIZE] = { 0 };
	char iv1[AES_BLOCK_SIZE] = { 0 };
	//memcpy(seed, "abcdefgh12345678zxcvbnml987654321qazwsxedcrfvtgbyhnujmikolp", sizeof(seed));

	yarrow256_ctx yctx;
	yarrow256_init(&yctx, 0, NULL);
	yarrow256_seed(&yctx, 16, (uint8_t *)seed);
	yarrow256_random(&yctx, sizeof(iv), (uint8_t *)iv);
	memcpy(iv1, iv, sizeof(iv1));

	//加密
	FILE *file = fopen(argv[1], "rb+");
	fseek(file, 0, SEEK_END);
	int flen = ftell(file);
	int i = flen;

	char init_data[16] = { 0 };
	char encrypted[16] = { 0 };

	while (i >= 0){
		fseek(file, flen - i, SEEK_SET);
		if (i == 0){
			memset(init_data, 16, sizeof(init_data));
		}
		else if (i < 16){
			fread(init_data, i, 1, file);
			memset(&init_data[i], 16 - i, 16 - i);
		}
		else {
			fread(init_data, 16, 1, file);
		}

		cbc_encrypt(&aes, (nettle_cipher_func *)aes256_encrypt, AES_BLOCK_SIZE, (uint8_t *)iv, sizeof(iv), (uint8_t *)encrypted, (uint8_t *)init_data);
		fseek(file, flen - i, SEEK_SET);
		fwrite(encrypted, 1, 16, file);
		i = i - 16;
	}
	//fclose(file);

	//解密
	//file = fopen(argv[1], "rb");
	fseek(file, 0, SEEK_END);
	flen = ftell(file);
	i = flen;

	FILE *file1 = fopen("res.txt", "wb");
	char decrypted[16] = { 0 };
	aes256_set_decrypt_key(&aes, (uint8_t *)key);
	while (i > 0){
		fseek(file, flen - i, SEEK_SET);
		fseek(file1, 0, SEEK_END);
		fread(init_data, 16, 1, file);
		//cbc_decrypt(&aes, (nettle_cipher_func *)(&aes, sizeof(aes), (uint8_t *)decrypted, (uint8_t *)init_data), AES_BLOCK_SIZE, (uint8_t *)iv1, sizeof(iv1), (uint8_t *)decrypted, (uint8_t *)init_data);
		cbc_decrypt(&aes, (nettle_cipher_func *)aes256_decrypt, AES_BLOCK_SIZE, (uint8_t *)iv1, sizeof(iv1), (uint8_t *)decrypted, (uint8_t *)init_data);
		//key.decrypt_n((byte *)init_data, (byte *)decrypted, 1);
		i = i - 16;
		if (i != 0){
			fwrite(decrypted, 1, 16, file1);
		}
		else{
			int len = decrypted[15];
			fwrite(decrypted, 1, 16 - len, file1);
		}
	}

	fclose(file);
	fclose(file1);

	return 0;
}
