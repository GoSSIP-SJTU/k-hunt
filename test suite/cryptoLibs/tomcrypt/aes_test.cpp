#include <tomcrypt.h>
//#include <tomcrypt_prng.h>
//#include <tomcrypt_cipher.h>

int main(int argc, char *argv[]){
	//密钥生成
	char userKey[32] = { 0 };
	char iv[16] = { 0 };
	//symmetric_key key;
	symmetric_CBC key;
	prng_state rng;
	int ret;

	if (register_cipher(&aes_desc) == -1){
		printf("register_cipher error!\n");
		return -1;
	}
	int cipher = find_cipher("aes");
	if (cipher == -1){
		printf("find_cipher error!\n");
		return -1;
	}

	memcpy(userKey, "abcdefghqwertyuiabcdefghqwertyui", sizeof(userKey));
	ret = register_prng(&sprng_desc);
	if (ret == -1){
		printf("register_prng error!\n");
		return -1;
	}

	ret = rng_make_prng(128, find_prng("sprng"), &rng, NULL);
	if (ret != CRYPT_OK){
		printf("rng_make_prng error!\n");
		return -1;
	}
	//ret = rng_get_bytes((unsigned char *)iv, 16, NULL);
	//ret = yarrow_read((unsigned char *)iv, 16, &rng);
	int size = 16;
	ret = sprng_export((unsigned char *)iv, (unsigned long *)&size, &rng);
	//ret = sprng_read((unsigned char *)iv, 16, &rng);
	if (ret != 0){
		printf("rng_get_bytes error!\n");
		return -1;
	}

	//int ret = aes_setup((unsigned char *)userKey, 32, 0, &key);
	ret = cbc_start(cipher, (unsigned char *)iv, (unsigned char *)userKey, 32, 0, &key);
	if (ret != CRYPT_OK){
		printf("cbc_start error!\n%s\n",error_to_string(ret));
		return -1;
	}
	

	//加密
	FILE *file = fopen(argv[1], "rb+");
	fseek(file, 0, SEEK_END);
	int flen = ftell(file);
	int i = flen;

	char init_data[16] = { 0 };
	char encrypted[16] = { 0 };
	//encrypted[16] = 0;

	while (i >= 0){
		fseek(file, flen - i, SEEK_SET);
		if (i == 0){
			memset(init_data, 16, 16);
		}
		else if (i < 16){
			fread(init_data, i, 1, file);
			memset(&init_data[i], 16 - i, 16 - i);
		}
		else {
			fread(init_data, 16, 1, file);
		}
		cbc_encrypt((unsigned char *)init_data, (unsigned char *)encrypted, 16, &key);
		//aes_ecb_encrypt((unsigned char *)init_data, (unsigned char *)encrypted, &key);
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
	ret = cbc_start(cipher, (unsigned char *)iv, (unsigned char *)userKey, 32, 0, &key);
	if (ret != CRYPT_OK){
		printf("cbc_start error!\n%s\n", error_to_string(ret));
		return -1;
	}
	while (i > 0){
		fseek(file, flen - i, SEEK_SET);
		fseek(file1, 0, SEEK_END);
		fread(init_data, 16, 1, file);
		cbc_decrypt((unsigned char *)init_data, (unsigned char *)decrypted, 16, &key);
		//aes_ecb_decrypt((unsigned char *)init_data, (unsigned char *)decrypted, &key);
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