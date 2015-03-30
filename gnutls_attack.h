
#include <gnutls/gnutls.h>
#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_cipher_int.h>
#include <gnutls_datum.h>
#include <gnutls_errors.h>
#include <random.h>
#include <crypto.h>
#include <unistd.h>
#include <time.h>
#include <string.h>

/*General*/
#define SUCCESS 1
#define FAILURE -1
#define ERROR   0
#define MAX_BUFFER_SIZE 48*1024

/*for Encrpytion*/
#define MAX_HASH_LENGTH 64
#define MAX_FILENAME 512
#define MAX_CIPHER_BLOCK_LENGTH 16
#define MAX_CIPHER_KEY_LENGTH 32
#define MAX_PAD_LENGTH 255
#define TLS_HANDSHAKE_HEADER_LENGTH 4
#define DTLS_HANDSHAKE_HEADER_LENGTH (TLS_HANDSHAKE_HEADER_LENGTH+8)

//handle->tag_size = _gnutls_mac_get_algo_len(me);
//int tag_size = _gnutls_auth_cipher_tag_len(&params->write.cipher_state);

typedef struct cipher_st_tag {
	const uint8_t *key;
	unsigned int key_size;
	const uint8_t *plaintext;
	unsigned int plaintext_size;
	const uint8_t *ciphertext;	/* also of plaintext_size */
    unsigned int ciphertext_size;
	const uint8_t *iv;
	unsigned int iv_size;
	gnutls_cipher_algorithm_t cipher;
}cipher_st;

typedef struct mac_st_tag {
    const uint8_t *key;
    unsigned int key_size;
    const uint8_t *plaintext;
    unsigned int plaintext_size;
    const uint8_t *output;
    unsigned int output_size;
    gnutls_mac_algorithm_t mac;
}mac_st;

/*Fuction Declaration*/
static int encrypt(gnutls_cipher_algorithm_t cipher, cipher_st* cipher_vector);

static int decrypt(gnutls_cipher_algorithm_t cipher, cipher_st* ectors);

static uint8_t* readPlaintext(size_t* length, char* file_name);

static void printStringToHex(uint8_t* , size_t length);

static void setHeader(uint8_t* buffer);
static int setPlaintext(uint8_t* buffer);
static int setMAC(gnutls_mac_algorithm_t mac,mac_st* mac_vector,
uint8_t* buffer,int position);
static int setPadding(uint8_t* buffer,uint16_t block_size);