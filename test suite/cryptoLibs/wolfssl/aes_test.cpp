#include <wolfssl\wolfcrypt\aes.h>
#include <wolfssl\wolfcrypt\random.h>

int main(int argc, char *argv[]){
	//密钥生成
	Aes key;
	WC_RNG rng;
	char userKey[32] = { 0 };
	char iv[16] = { 0 };
	char iv1[16] = { 0 };
	memcpy(userKey, "abcdefgh12345678abcdefgh12345678", sizeof(userKey));
	wc_InitRng(&rng);
	wc_RNG_GenerateBlock(&rng, (byte *)iv, 16);
	memcpy(iv1, iv, sizeof(iv1));

	//加密
	FILE *file = fopen(argv[1], "rb+");
	fseek(file, 0, SEEK_END);
	int flen = ftell(file);
	int i = flen;

	char init_data[16] = { 0 };
	char encrypted[16] = { 0 };
	//encrypted[16] = 0;
	wc_AesSetKey(&key, (unsigned char *)userKey, 32, (unsigned char *)iv, 0);

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
		wc_AesCbcEncrypt(&key, (unsigned char *)encrypted, (unsigned char *)init_data, 16);
		
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
	wc_AesSetKey(&key, (unsigned char *)userKey, 32, (unsigned char *)iv1, 1);

	while (i > 0){
		fseek(file, flen - i, SEEK_SET);
		fseek(file1, 0, SEEK_END);
		fread(init_data, 16, 1, file);
		wc_AesCbcDecrypt(&key, (unsigned char *)decrypted, (unsigned char *)init_data, 16);
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
