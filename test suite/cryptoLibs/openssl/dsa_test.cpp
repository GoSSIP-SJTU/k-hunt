#include <stdio.h>  
#include <string.h>  
#include <openssl\dsa.h>
#include <openssl\bn.h>


int init_dsa_key(DSA **dsa, DSA **dsa_pri, DSA **dsa_pub){
	int ret = 0;
	*dsa = DSA_new();
	DSA_generate_parameters_ex(*dsa, 1024, NULL, 0, NULL, NULL, NULL);

	ret = DSA_generate_key(*dsa);


	*dsa_pri = DSA_new();
	(*dsa_pri)->p = BN_dup((*dsa)->p);
	(*dsa_pri)->q = BN_dup((*dsa)->q);
	(*dsa_pri)->g = BN_dup((*dsa)->g);
	(*dsa_pri)->priv_key = BN_dup((*dsa)->priv_key);

	*dsa_pub = DSA_new();
	(*dsa_pub)->p = BN_dup((*dsa)->p);
	(*dsa_pub)->q = BN_dup((*dsa)->q);
	(*dsa_pub)->g = BN_dup((*dsa)->g);
	(*dsa_pub)->pub_key = BN_dup((*dsa)->pub_key);

	return 0;
}


int test_dsa(char *buf1, int len1, DSA *dsa_pri, DSA *dsa_pub){
	int ret = 0;
	int dsa_len = DSA_size(dsa_pri);
	int len2 = dsa_len;
	char *buf2 = (char *)malloc(len2);

	ret = DSA_sign(0, (unsigned char *)buf1, len1, (unsigned char *)buf2, (unsigned int *)&len2, dsa_pri);


	ret = DSA_verify(0, (unsigned char *)buf1, len1, (unsigned char *)buf2, len2, dsa_pub);

	if (ret)
		puts("verify ok!");
	else
		puts("verify error!");

	return ret;
}

#define BUF_SIZE 64  
int main(){
	int ret = 0;
	DSA *dsa = NULL;
	DSA *dsa_pri = NULL;
	DSA *dsa_pub = NULL;
	int i, len = BUF_SIZE;
	char *buf = (char *)malloc(len);
	memset(buf, 0, len);
	for (i = 0; i<BUF_SIZE; i++){
		buf[i] = i % 256;
	}

	init_dsa_key(&dsa, &dsa_pri, &dsa_pub);
	test_dsa(buf, len, dsa_pri, dsa_pub);

	DSA_free(dsa);
	DSA_free(dsa_pri);
	DSA_free(dsa_pub);
	free(buf);
	return ret;
}