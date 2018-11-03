#define WOLFSSL_KEY_GEN
#include <wolfssl\options.h>
#include <IDE\WIN\user_settings.h>
#include <wolfssl\wolfcrypt\rsa.h>
#include <wolfssl\wolfcrypt\error-crypt.h>

int main(int argc, char *argv[]){
	FILE *file = fopen(argv[1], "r");
	fseek(file, 0L, SEEK_END);
	int flen = ftell(file);
	char init_data[2048] = { 0 };
	fseek(file, 0L, SEEK_SET);
	fread(init_data, flen, 1, file);
	init_data[flen] = 0;
	fclose(file);
	printf("init_data\n%s\n\n", init_data);

	char encrypted[4096] = {};
	char decrypted[4096] = {};
	RsaKey key;
	WC_RNG rng;

	memset(encrypted, 0, sizeof(encrypted));
	memset(decrypted, 0, sizeof(decrypted));

	int ret = wc_InitRsaKey(&key, 0);
	if (ret != 0){
		printf("wc_InitRsaKey error!\n%s\n", wc_GetErrorString(ret));
		return -1;
	}
	
	ret = wc_InitRng(&rng);
	if (ret != 0){
		printf("wc_InitRng error!\n%s\n", wc_GetErrorString(ret));
		return -1;
	}

	ret = wc_MakeRsaKey(&key, 2048, 65537, &rng);
	if (ret != 0){
		printf("wc_MakeRsaKey error!\n%s\n", wc_GetErrorString(ret));
		return -1;
	}

	int elen = wc_RsaPublicEncrypt_ex((byte *)init_data, flen, (byte *)encrypted, sizeof(encrypted), &key, &rng, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA, WC_MGF1SHA1, NULL, 0);
	//int elen = wc_RsaPublicEncrypt((unsigned char *)init_data, flen, (unsigned char *)encrypted, sizeof(encrypted), &key, &rng);
	if (elen < 0){
		printf("wc_RsaPublicEncrypt error!\n%s\n", wc_GetErrorString(elen));
		return -1;
	}

	file = fopen(argv[1], "wb");
	fwrite(encrypted, 1, elen, file);
	fclose(file);
	printf("encrypted\nlength: %d\n%s\n\n", elen, encrypted);

	//decrypted
	file = fopen(argv[1], "rb");
	fseek(file, 0L, SEEK_END);
	flen = ftell(file);
	memset(init_data, 0, sizeof(init_data));
	fseek(file, 0L, SEEK_SET);
	fread(init_data, flen, 1, file);
	init_data[flen] = 0;
	fclose(file);
	printf("init_data\nlength: %d\n%s\n\n", flen, init_data);

	ret = wc_RsaSetRNG(&key, &rng);
	if (ret != 0){
		printf("wc_RsaSetRNG error!\n%s\n", wc_GetErrorString(ret));
		return -1;
	}

	int dlen = wc_RsaPrivateDecrypt_ex((byte *)init_data, flen, (byte *)decrypted, sizeof(decrypted), &key, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA, WC_MGF1SHA1, NULL, 0);
	//int dlen = wc_RsaPrivateDecrypt((unsigned char *)encrypted, elen, (unsigned char *)decrypted, sizeof(decrypted), &key);
	if (dlen < 0){
		printf("wc_RsaPrivateDecrypt error!%d\n%s\n", dlen, wc_GetErrorString(dlen));
		return -1;
	}
	
	file = fopen(argv[1], "wb");
	fwrite(decrypted, 1, dlen, file);
	fclose(file);
	printf("decrypted\nlength: %d\n%s\n\n", dlen, decrypted);

	//wc_FreeRng(&rng);
	//wc_FreeRsaKey(&key);
	//free(init_data);
	return 0;
}