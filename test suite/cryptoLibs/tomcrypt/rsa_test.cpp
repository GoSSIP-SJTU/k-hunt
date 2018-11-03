#include <tomcrypt.h>

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

	char encrypted[1024] = {};
	char decrypted[1024] = {};
	rsa_key key;

	memset(encrypted, 0, sizeof(encrypted));
	memset(decrypted, 0, sizeof(decrypted));

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

	int ret = rsa_make_key(NULL, prng_id, 2048/8, 65537, &key);
	if (ret != 0){
		printf("rsa_make_key error!\n%s\n", error_to_string(ret));
		return 1;
	}

	int elen = sizeof(encrypted);
	ret = rsa_encrypt_key((unsigned char *)init_data, flen, (unsigned char *)encrypted, (unsigned long *)&elen, (unsigned char *)"test", strlen("test"), NULL, prng_id, hash_id, &key);
	if (ret != 0){
		printf("rsa_encrypt_key error!\n%s\n", error_to_string(ret));
		return 1;
	}

	file = fopen(argv[1], "wb");
	fwrite(encrypted, elen, 1, file);
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

	int dlen = sizeof(decrypted);
	int res;
	ret = rsa_decrypt_key((unsigned char *)init_data, flen, (unsigned char *)decrypted, (unsigned long *)&dlen, (unsigned char *)"test", strlen("test"), hash_id, &res, &key);
	if (ret != 0){
		printf("rsa_decrypt_key error!\n%s\n", error_to_string(ret));
		return 1;
	}

	file = fopen(argv[1], "wb");
	fwrite(decrypted, dlen, 1, file);
	fclose(file);
	printf("decrypted\nlength: %d\n%s\n\n", dlen, decrypted);

	//free(init_data);
	return 0;
}