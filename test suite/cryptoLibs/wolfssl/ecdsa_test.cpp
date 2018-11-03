#define WOLFSSL_KEY_GEN
#define HAVE_ECC
#include <wolfssl\wolfcrypt\ecc.h>

int main(int argc, char *argv[]){
	FILE *file = fopen(argv[1], "r");
	fseek(file, 0L, SEEK_END);
	int flen = ftell(file);
	char *init_data = (char *)malloc(flen + 1);
	if (init_data == NULL){
		fclose(file);
		return 0;
	}
	fseek(file, 0L, SEEK_SET);
	fread(init_data, flen, 1, file);
	init_data[flen] = 0;
	fclose(file);
	printf("init_data\n%s\n\n", init_data);

	char sign[4096] = {};
	ecc_key key;
	RNG rng;

	memset(sign, 0, sizeof(sign));

	wc_ecc_init(&key);
	wc_InitRng(&rng);

	wc_ecc_make_key(&rng, 32, &key);

	int slen;
	int ret = wc_ecc_sign_hash((unsigned char *)init_data, flen, (unsigned char *)sign, (word32 *)&slen, &rng, &key);
	if (ret != 0){
		printf("wc_ecc_sign_hash error!\n");
		return -1;
	}
	else printf("wc_ecc_sign_hash ok!\n");

	int stat;
	ret = wc_ecc_verify_hash((unsigned char *)sign, slen, (unsigned char *)init_data, flen, &stat, &key);
	if (stat != 1){
		printf("wc_ecc_verify_hash error!\n");
		return -1;
	}
	else printf("wc_ecc_verify_hash ok!\n");
	return 0;
}