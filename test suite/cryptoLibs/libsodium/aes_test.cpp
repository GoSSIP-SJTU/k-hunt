#include <sodium.h>
#include <romangol.h>

#define MESSAGE (const u1 *) "test"
#define MESSAGE_LEN 4
#define ADDITIONAL_DATA (const u1 *) "123456"
#define ADDITIONAL_DATA_LEN 6

int main()
{
	u1 nonce[crypto_aead_aes256gcm_NPUBBYTES];
	u1 key[crypto_aead_aes256gcm_KEYBYTES];
	u1 ciphertext[MESSAGE_LEN + crypto_aead_aes256gcm_ABYTES];
	u8 ciphertext_len;

	sodium_init();
	if (crypto_aead_aes256gcm_is_available() == 0)
	{
	    abort(); /* Not available on this CPU */
	}

	crypto_aead_aes256gcm_keygen(key);
	randombytes_buf(nonce, sizeof nonce);

	crypto_aead_aes256gcm_encrypt(ciphertext, &ciphertext_len,
	                              MESSAGE, MESSAGE_LEN,
	                              ADDITIONAL_DATA, ADDITIONAL_DATA_LEN,
	                              NULL, nonce, key);

	u1 decrypted[MESSAGE_LEN];
	u8 decrypted_len;
	if (ciphertext_len < crypto_aead_aes256gcm_ABYTES ||
	    crypto_aead_aes256gcm_decrypt(decrypted, &decrypted_len,
	                                  NULL,
	                                  ciphertext, ciphertext_len,
	                                  ADDITIONAL_DATA,
	                                  ADDITIONAL_DATA_LEN,
	                                  nonce, key) != 0) {
	    /* message forged! */
	}
}