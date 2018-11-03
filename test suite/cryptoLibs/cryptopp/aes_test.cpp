#include <aes.h>
#include <rng.h>
#include <osrng.h>
#include <modes.h>
#include <stdio.h>
#include <stdlib.h>

using namespace CryptoPP;
using namespace std;

int main(int argc, char *argv[]){
	//密钥生成
	//AESEncryption aesencryptor;
	//AESDecryption aesdecryptor;
	char key[32] = { 0 };
	char iv[16] = { 0 };
	AutoSeededRandomPool rng;
	//RandomNumberGenerator rng;

	rng.GenerateBlock((byte *)iv, 16);
	printf("%s\n", iv);

	memcpy(key, "abcdefgh12345678abcdefgh12345678", 32);
	CBC_Mode<AES>::Encryption encryptor;// ((byte *)key, 32, (byte *)iv);
	CBC_Mode<AES>::Decryption decryptor;// ((byte *)key, 32, (byte *)iv);
	encryptor.SetKeyWithIV((byte *)key, 32, (byte *)iv);
	decryptor.SetKeyWithIV((byte *)key, 32, (byte *)iv);
	//aesencryptor.SetKey((byte *)key, 16);
	//aesencryptor.SetKeyWithIV((byte *)key, 16, (byte *)iv, 16);
	//aesdecryptor.SetKey((byte *)key, 16);
	//aesdecryptor.SetKeyWithIV((byte *)key, 16, (byte *)iv, 16);

	//加密
	FILE *file = fopen(argv[1], "rb+");
	fseek(file, 0, SEEK_END);
	int flen = ftell(file);
	int i = flen;

	char init_data[16] = { 0 };
	char encrypted[16] = { 0 };
	//string encrypted;
	char xorblock[16] = { 0 };
	//encrypted[16] = 0;

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
		
		/*StringSource ss(init_data, true,
			new StreamTransformationFilter(encryptor,
			new StringSink(encrypted)
			) // StreamTransformationFilter      
			); // StringSource*/

		encryptor.ProcessData((byte *)encrypted, (byte *)init_data, 16);
		//aesencryptor.ProcessAndXorBlock((byte *)init_data, (byte *)xorblock, (byte *)encrypted);
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

	while (i > 0){
		fseek(file, flen - i, SEEK_SET);
		fseek(file1, 0, SEEK_END);
		fread(init_data, 16, 1, file);
		decryptor.ProcessData((byte *)decrypted, (byte *)init_data, 16);
		//aesdecryptor.ProcessAndXorBlock((byte *)init_data, (byte *)xorblock, (byte *)decrypted);
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