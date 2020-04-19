#include "cryptography.h"

//Hardcoded Key
unsigned const char AES_KEY[KEY_SIZE + 1] = "I$'5%mqz`Q,yG/EZ3O3y]U'eU<7'F:)T";

unsigned char* addPadding(unsigned char * data, unsigned * length){
	unsigned lastBlock = (*length / AES_BLOCK_SIZE)*AES_BLOCK_SIZE; //mathmatically looks dumb but its integer division
	unsigned char remainder = AES_BLOCK_SIZE - (*length % AES_BLOCK_SIZE);
	data = (unsigned char*)realloc(data, *length + (int)remainder);
	if (data == NULL)
		return NULL;
	memset(data + (lastBlock + (*length%AES_BLOCK_SIZE)), remainder, (int)remainder);
	*length = *length + (int)remainder;
	return data;
}

unsigned char* removePadding(unsigned char * data, unsigned length){
	unsigned pad = *(data + length - 1);
	//printf("%d\n", pad);
	memset(data + (length - pad), '\0', pad);
	data = (unsigned char*)realloc(data, length-pad);
	//if (data == NULL)
	//	return NULL;
	return data;
}

unsigned char * genRandBytes(int size){
	unsigned char *val = (unsigned char*)malloc(size+1);
	if (val == NULL)
		return NULL;
	int rand = RAND_bytes(val, size);
	if (rand == 0)
		return NULL; //error occurred
	*(val + size) = '\0';
	return val;
}

 crypto * encryptString(unsigned char * data, unsigned length){
	crypto * encryption = (crypto*)malloc(sizeof(crypto));
	if (encryption == NULL)
		return NULL;
	encryption->IV = genRandBytes(IV_SIZE);
	if(encryption->IV == NULL)
		return NULL;

	//begin encryption stage using AES-cbc 256-bit
	EVP_CIPHER_CTX *context;
	context = EVP_CIPHER_CTX_new();
	if (context != NULL) {
		if (EVP_EncryptInit_ex(context, EVP_aes_256_cbc(), NULL, AES_KEY, encryption->IV)) {
			EVP_CIPHER_CTX_set_padding(context, 0);
			data = addPadding(data, &length);
			if (data != NULL) {
				int ct_len = 0;// , ct_len_calc = ((length / AES_BLOCK_SIZE + 1)*AES_BLOCK_SIZE); //calculation of ciphertext size, accounting for padding
				encryption->ciphertext = (unsigned char*)malloc(length);
				if (encryption->ciphertext != NULL) {
					if (EVP_EncryptUpdate(context, encryption->ciphertext, &ct_len, data, length)) {
						if (length >= ct_len) {
							//else potential buffer overflow
							if (EVP_EncryptFinal_ex(context, (encryption->ciphertext) + ct_len, &ct_len)) {
								/* Clean up */
								EVP_CIPHER_CTX_free(context);
								encryption->ct_len = length;
								return encryption;
							}
						}
					}
				}
			}
		}
	}
	free(encryption->IV);
	free(encryption);
	ERR_print_errors_fp(stderr);
	return NULL;
}

unsigned char * decryptString(crypto* data){
	if (data == NULL || data->ciphertext == NULL || data->IV == NULL || data->ct_len <= 0)
		return NULL;
	EVP_CIPHER_CTX *context;
	context = EVP_CIPHER_CTX_new();
	if (context != NULL) {
		if (EVP_DecryptInit_ex(context, EVP_aes_256_cbc(), NULL, AES_KEY, data->IV)) {
			EVP_CIPHER_CTX_set_padding(context, 0); 
			/*disable padding due to bug where it fills the plaintext buffer with more decrypted data than it claims it does
			and causes the final stage of decryption to see invalid padding; potential alternitive is to adjust the decrypt update
			return size to padded size - size so that just the size of the padding is left by the final stage*/
			int pt_len = data->ct_len, pt_len_actual = 0;
			unsigned char* plaintext = (unsigned char*)malloc(data->ct_len+1); //assumes ciphertext size >= plaintext size
			if (plaintext != NULL) {
				if (EVP_DecryptUpdate(context, plaintext, &pt_len, data->ciphertext, data->ct_len)) {
					pt_len_actual += pt_len;
					if (EVP_DecryptFinal_ex(context, plaintext + pt_len, &pt_len)) {
						pt_len_actual += pt_len;
						/* Clean up */
						EVP_CIPHER_CTX_free(context);
						*(plaintext + data->ct_len) = '\0';
						plaintext = removePadding(plaintext, strlen(plaintext));
						if (plaintext != NULL) {
							return plaintext;
						}
					}
				}
			}
		}
	}
	ERR_print_errors_fp(stderr);
	return NULL;
}

int encryptToFile(int fileDescriptor){
	int fileSize = lseek(fileDescriptor, 0, SEEK_END);
	char* fileData = getFileData(fileDescriptor); //This mode encrypts the file WITH the HMAC
	crypto* encryption = encryptString(fileData, fileSize);
	if(encryption == NULL || encryption->IV == NULL || encryption->ciphertext == NULL || encryption->ct_len <= 0)
		return 0;
	int offset = 0, remaining = encryption->ct_len;
	lseek(fileDescriptor, 0, SEEK_SET);
	while (remaining > 0) {
		int ret = write(fileDescriptor, (encryption->ciphertext) + offset, remaining);
		if (ret < 0)
			return 0;
		remaining -= ret;
		offset += ret;
	}
	offset = 0; remaining = IV_SIZE;
	while (remaining > 0) {
		int ret = write(fileDescriptor, (encryption->IV) + offset, remaining);
		if (ret < 0)
			return 0;
		remaining -= ret;
		offset += ret;
	}
	return 1;
}

crypto * genCryptoFromFile(int fileDescriptor){
	unsigned char* fileData = getFileData(fileDescriptor);
	int fileSize = lseek(fileDescriptor, 0, SEEK_END);
	crypto* data = (crypto*)malloc(sizeof(crypto));
	if (data == NULL)
		return NULL;
	data->ct_len = fileSize-IV_SIZE;
	unsigned char* IV = (unsigned char*)malloc(IV_SIZE+1);
	if (IV == NULL)
		return NULL;
	unsigned IV_index = (fileSize - IV_SIZE);
	memcpy(IV, fileData+IV_index, IV_SIZE);
	*(IV + IV_SIZE) = '\0';
	data->ciphertext = (unsigned char*)malloc(data->ct_len);
	if (data->ciphertext == NULL)
		return NULL;
	data->IV = IV;
	memcpy(data->ciphertext, fileData, data->ct_len);
	free(fileData);
	return data;
}
