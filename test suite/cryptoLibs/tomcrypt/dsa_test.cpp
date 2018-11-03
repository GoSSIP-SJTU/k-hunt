#include <tomcrypt.h>

int main(int argc, char *argv[]){
	FILE *file = fopen(argv[1], "r");
	fseek(file, 0L, SEEK_END);
	int flen = ftell(file);
	char init_data[4096] = { 0 };
	fseek(file, 0L, SEEK_SET);
	fread(init_data, flen, 1, file);
	init_data[flen] = 0;
	printf("init_data\n%s\n\n", init_data);

	char sign[1024] = {};
	dsa_key key;

	memset(sign, 0, sizeof(sign));

	//注册一个伪随机数生成器
	if (register_prng(&sprng_desc) == -1) {
		printf("Error registering sprng");
		return EXIT_FAILURE;
	}

	//注册一个数学库
	ltc_mp = ltm_desc;
	if (register_hash(&sha1_desc) == -1) {
		printf("Error registering sha1");
		return EXIT_FAILURE;
	}

	int hash_id = find_hash("sha1");
	if (hash_id == -1){
		printf("find_hash error !\n");
		return -1;
	}
	int prng_id = find_prng("sprng");
	if (prng_id == -1){
		printf("find_prng error!\n");
		return -1;
	}

	int ret = dsa_make_key(NULL, prng_id, 20, 128, &key);
	if (ret != 0){
		printf("dsa_make_key error!\n%s\n", error_to_string(ret));
		return 1;
	}

	int slen;
	ret = dsa_sign_hash((unsigned char *)init_data, (unsigned long)flen, (unsigned char *)sign, (unsigned long *)&slen, NULL, prng_id, &key);
	if (ret != 0){
		printf("dsa_sign_hash error!\n%s\n", error_to_string(ret));
		return 1;
	}
	else printf("dsa_sign_hash ok!\n");

	int res;
	ret = dsa_verify_hash((unsigned char *)sign, slen, (unsigned char *)init_data, flen, &res, &key);
	if (ret != 0){
		printf("dsa_verify_hash error!\n%s\n", error_to_string(ret));
		return 1;
	}
	else printf("dsa_verify_hash ok!\n");

	return 0;
}