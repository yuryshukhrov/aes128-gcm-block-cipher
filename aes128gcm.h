/*	File: aes128gcm.h
 *	Synopsis: AES encryption with 128 bit key in GCM mode
 *	Author: yury.shukhrov@gmail.com
 *	Date: 24.11.2014
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "aes128e.h"

/* Under the 16-byte (128-bit) key "k",
and the 12-byte (96-bit) initial value "IV",
encrypt the plaintext "plaintext" and store it at "ciphertext".
The length of the plaintext is a multiple of 16-byte (128-bit) given by len_p (e.g., len_p = 2 for a 32-byte plaintext).
The length of the ciphertext "ciphertext" is len_p*16 bytes.
The authentication tag is obtained by the 16-byte tag "tag".
For the authentication an additional data "add_data" can be added.
The number of blocks for this additional data is "len_ad" (e.g., len_ad = 1 for a 16-byte additional data).
*/
void aes128gcm(unsigned char *ciphertext, unsigned char *tag, const unsigned char *k,
	const unsigned char *IV, const unsigned char *plaintext,
	const unsigned long len_p, const unsigned char* add_data, const unsigned long len_ad);

void phex(uint8_t *str);
void shift_right_block(uint8_t *v);
static void gf_mult(const uint8_t *x, const uint8_t *y, uint8_t *z);
void xor_block(uint8_t *dst, const uint8_t *src);
uint32_t bit_32_to_int(uint8_t *a);
void int_to_32_bit(uint8_t *a, uint32_t val);
uint64_t bit_64_to_int(const uint8_t *a);
void int_to_64_bit(uint8_t *a, uint64_t val);
void inc_32_bit(uint8_t *block);
void init_hash_subkey(const uint8_t *key, uint8_t **H);
void init_pre_counter_block(const uint8_t *iv, uint8_t **J);
void prepare_gctr(uint8_t *key, const uint8_t *J, const uint8_t *in, size_t in_len, uint8_t *out);
void gctr(uint8_t *key, const uint8_t *icb, const uint8_t *in, size_t in_len, uint8_t *out);
void prepare_ghash(const uint8_t *H, const uint8_t *aad, size_t aad_len, const uint8_t *crypt, size_t crypt_len, uint8_t **S);
void ghash(const uint8_t *h, const uint8_t *x, size_t xlen, uint8_t *y);