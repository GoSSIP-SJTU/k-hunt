#include <string.h>
#include <stdio.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl\ecdh.h>

int    main()
{
	EC_KEY                *key1, *key2;
	const EC_POINT            *pubkey1, *pubkey2;
	EC_GROUP           *group1, *group2;
	int                         ret, nid, size, i, sig_len;
	unsigned char*signature, digest[20];
	BIO                      *berr;
	EC_builtin_curve    *curves;
	int                                crv_len;
	char               shareKey1[128], shareKey2[128];
	int                         len1, len2;

	/* ����EC_KEY���ݽṹ */
	key1 = EC_KEY_new();
	if (key1 == NULL)
	{
		puts("EC_KEY_new err!");
		return -1;
	}
	key2 = EC_KEY_new();
	if (key2 == NULL)
	{
		puts("EC_KEY_new err!");
		return -1;
	}
	/* ��ȡʵ�ֵ���Բ���߸��� */
	crv_len = EC_get_builtin_curves(NULL, 0);
	curves = (EC_builtin_curve *)malloc(sizeof(EC_builtin_curve) * crv_len);
	/* ��ȡ��Բ�����б� */
	EC_get_builtin_curves(curves, crv_len);
	/*
	nid=curves[0].nid;���д���ԭ������Կ̫��
	*/
	/* ѡȡһ����Բ���� */
	nid = curves[25].nid;
	/* ����ѡ�����Բ����������Կ����group */
	group1 = EC_GROUP_new_by_curve_name(nid);
	if (group1 == NULL)
	{
		puts("EC_GROUP_new_by_curve_name err!");
		return -1;
	}
	group2 = EC_GROUP_new_by_curve_name(nid);
	if (group1 == NULL)
	{
		puts("EC_GROUP_new_by_curve_name err!");
		return -1;
	}
	/* ������Կ���� */
	ret = EC_KEY_set_group(key1, group1);
	if (ret != 1)
	{
		puts("EC_KEY_set_group err.");
		return -1;
	}
	ret = EC_KEY_set_group(key2, group2);
	if (ret != 1)
	{
		puts("EC_KEY_set_group err.");
		return -1;
	}
	/* ������Կ */
	ret = EC_KEY_generate_key(key1);
	if (ret != 1)
	{
		puts("EC_KEY_generate_key err.");
		return -1;
	}
	ret = EC_KEY_generate_key(key2);
	if (ret != 1)
	{
		puts("EC_KEY_generate_key err.");
		return -1;
	}
	/* �����Կ */
	ret = EC_KEY_check_key(key1);
	if (ret != 1)
	{
		puts("check key err.");
		return -1;
	}
	/* ��ȡ��Կ��С */
	size = ECDSA_size(key1);
	printf("size %d \n", size);
	for (i = 0; i<20; i++)
		memset(&digest[i], i + 1, 1);
	signature = (unsigned char *)malloc(size);
	ERR_load_crypto_strings();


	/* ǩ�����ݣ�����δ��ժҪ���ɽ�digest�е����ݿ�����sha1ժҪ��� */
	ret = ECDSA_sign(0, digest, 20, signature, (unsigned int *)&sig_len, key1);
	if (ret != 1)
	{

		puts("sign err!");
		return -1;
	}
	/* ��֤ǩ�� */
	ret = ECDSA_verify(0, digest, 20, signature, sig_len, key1);
	if (ret != 1)
	{

		puts("ECDSA_verify err!");
		return -1;
	}
	/* ��ȡ�Է���Կ������ֱ������ */
	pubkey2 = EC_KEY_get0_public_key(key2);
	/* ����һ���Ĺ�����Կ */
	len1 = ECDH_compute_key(shareKey1, 128, pubkey2, key1, NULL);
	pubkey1 = EC_KEY_get0_public_key(key1);
	/* ������һ��������Կ */
	len2 = ECDH_compute_key(shareKey2, 128, pubkey1, key2, NULL);
	if (len1 != len2)
	{
		puts("err");
	}
	else
	{
		ret = memcmp(shareKey1, shareKey2, len1);
		if (ret == 0)
			puts("���ɹ�����Կ�ɹ�");
		else
			puts("���ɹ�����Կʧ��");
	}
	puts("test ok!");
	EC_KEY_free(key1);
	EC_KEY_free(key2);
	free(signature);
	free(curves);
	return 0;
}