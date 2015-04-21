
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
	uint8_t *key;
	unsigned int key_size;
	uint8_t *plaintext;
	unsigned int plaintext_size;
	uint8_t *ciphertext;	/* also of plaintext_size */
    unsigned int ciphertext_size;
	uint8_t *iv;
	unsigned int iv_size;
	gnutls_cipher_algorithm_t cipher;
}cipher_st;

typedef struct mac_st_tag {
    uint8_t *key;
    unsigned int key_size;
    uint8_t *plaintext;
    unsigned int plaintext_size;
    uint8_t *output;
    unsigned int output_size;
    gnutls_mac_algorithm_t mac;
}mac_st;

/*Fuction Declaration*/
static int encrypt(cipher_st* cipher_vector);

static int decrypt(cipher_st* ectors, mac_st* mac_vector);

static uint8_t* read_plaintext(int* length, char* file_name);

static void print_string_to_hex(uint8_t* src, int from, int length);

static void set_header(uint8_t* buffer);
static int set_plaintext(uint8_t* buffer);
static int calculate_MAC(mac_st* mac_vector);
static int set_padding(uint8_t* buffer,uint16_t block_size, int position);

static int gnutls_cipher_add_auth_t(unsigned int len);
static void dummy_wait_t(record_parameters_st* params,
		       gnutls_datum_t* plaintext, unsigned int pad_failed,
		       unsigned int pad, unsigned int total);
static void rdtsc(uint64_t* result);
