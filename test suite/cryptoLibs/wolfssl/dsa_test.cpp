#define WOLFSSL_KEY_GEN
#include <wolfssl\wolfcrypt\dsa.h>

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
	DsaKey key;
	RNG rng;

	memset(sign, 0, sizeof(sign));

	wc_InitDsaKey(&key);
	wc_InitRng(&rng);

	wc_MakeDsaParameters(&rng, 1024, &key);
	wc_MakeDsaKey(&rng, &key);

	int ret = wc_DsaSign((byte *)init_data, (byte *)sign, &key, &rng);
	if (ret != 0){
		printf("wc_DsaSign error!\n");
		return -1;
	}
	else printf("wc_DsaSign ok!\n");

	int ans;
	ret = wc_DsaVerify((unsigned char *)init_data, (unsigned char *)sign, &key, &ans);
	if (ans != 1){
		printf("wc_DsaVerify error!\n");
		return -1;
	}
	else printf("wc_DsaVerify ok!\n");

	return 0;
}