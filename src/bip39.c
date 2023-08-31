/*
 * Copyright (c) 2023 Siddharth Chandrasekaran <sidcha.dev@gmail.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @brief BIP-39 implementation
 *
 * | key_len | key_bits(A) | cs_bits(B) |   A+B  |  MS  |
 * +---------+-------------+------------+--------+------+
 * |   16    |   128       |     4      |   132  |  12  |
 * |   20    |   160       |     5      |   165  |  15  |
 * |   24    |   192       |     6      |   198  |  18  |
 * |   28    |   224       |     7      |   231  |  21  |
 * |   32    |   256       |     8      |   264  |  24  |
 *
 * cs_bits = checksum bits;
 * MS = Mnemonic Sentence length in words
 *
 * Reference:
 * - https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 */

#include <stdio.h>
#include <string.h>

#include "bip39.h"
#include "bip39_en.h"
#include "sha256.h"

#define bit_set_u8(m, b)	 m[b / 8] |= (1UL << (b % 8))
#define is_bit_set_u8(m, b)	((m[b / 8]  & (1UL << (b % 8))) == (1UL << (b % 8)))
#define bits_to_bytes(b)	(b + 7) / 8
#define bit_mask(n) ((1UL << (n + 1)) - 1)

static inline uint8_t u8_reverse_bits(uint8_t b)
{
	b = (((b & 0xaa) >> 1) | ((b & 0x55) << 1));
	b = (((b & 0xcc) >> 2) | ((b & 0x33) << 2));
	return ((b >> 4) |  (b << 4));
}

static inline uint16_t u16_reverse_bits(uint16_t x)
{
	x = (((x & 0xaaaa) >> 1) | ((x & 0x5555) << 1));
	x = (((x & 0xcccc) >> 2) | ((x & 0x3333) << 2));
	x = (((x & 0xf0f0) >> 4) | ((x & 0x0f0f) << 4));
	return((x >> 8) | (x << 8));
}

static const char *bip39_mnemonic_word(int bits)
{
	if ((bits & ~0x7ff) != 0) // at most 11 bits
		return NULL;

	return bip39_word_list_en[bits];
}

static int bip39_mnemonic_word_to_bits(const char *word)
{
	int ret, mid, left = 0, right = 2048;

	while (left < right) {
		mid = (left + right) / 2;
		ret = strcmp(word, bip39_word_list_en[mid]);
		if (ret == 0)
			return mid;
		if (ret < 0)
			right = mid;
		else
			left = mid + 1;
	}
	return -1;
}

/**
 * @brief bit_range_extract: extract a range of bits [from, to] from src
 * and put it into dst.
 *
 *    Input (src):
 *    0      7  8     15  16    23  24    31  32    39
 *    |      |  |      |  |      |  |      |  |      |
 *    01101001  01010010  01010001  11111010  01001000
 *                 |           |
 *    Range ---> [ 11         21 ]
 *
 *    Output (dst):
 *    Left Justified:          Right Justified:
 *    0      7  8     15       0      7  8     15
 *    |      |  |      |       |     |  |      |
 *    10010010  10000000       0000100  10010100
 */
static void bit_range_extract(uint8_t *dst, size_t base,
			      uint8_t *src, size_t from, size_t to,
			      bool right_justified)
{
	const size_t nr_bits = to - from;
	const size_t free_bits = (bits_to_bytes(nr_bits) * 8) - nr_bits;
	size_t write_to = base + (right_justified ? free_bits : 0);

	while (from < to) {
		if (is_bit_set_u8(src, from))
			bit_set_u8(dst, write_to);
		from += 1;
		write_to += 1;
	}
}

const char *bip39_word_is_valid(const char *word)
{
	int pos = bip39_mnemonic_word_to_bits(word);

	return (pos == -1) ? NULL : bip39_word_list_en[pos];
}

int bip39_key_to_mnemonic_words(const uint8_t *key, const int key_len,
				const char *words[MS_MAX_WORDS], int *p_nr_words)
{
	int i, bits = 0;
	const int nr_words = ((key_len * 8) + 10) / 11;
	uint8_t mnemonic_bits[2]; // 11 bits per chunk, so 2 bytes
	uint8_t digest[SHA256_LEN];
	uint8_t key_with_checksum[KEY_MAX_LEN + 1];

	if (key_len < 16 || key_len > 32 || ((key_len * 8) % 32) != 0)
		return -1;

	compute_sha256(key, key_len, digest);
	memcpy(key_with_checksum, key, key_len);
	key_with_checksum[key_len] = digest[0];
	for (i = 0; i < key_len + 1; i++)
		key_with_checksum[i] = u8_reverse_bits(key_with_checksum[i]);
	for (i = 0; i < nr_words; i++) {
		memset(mnemonic_bits, 0, sizeof(mnemonic_bits));
		bit_range_extract(mnemonic_bits, 0,
				  key_with_checksum, 11 * i, 11 * (i + 1),
				  true);
		bits = (u8_reverse_bits(mnemonic_bits[0]) << 8) |
		        u8_reverse_bits(mnemonic_bits[1]);
		if ((words[i] = bip39_mnemonic_word(bits)) == NULL)
			return -2;
	}
	*p_nr_words = nr_words;
	return 0;
}

int bip39_key_from_mnemonic_words(const char *words[MS_MAX_WORDS], int nr_words,
				  uint8_t key[KEY_MAX_LEN], int *p_key_len)
{
	uint8_t digest[SHA256_LEN];
	int i, bits;
	uint8_t mnemonic_bits[2]; // 11 bits per chunk, so 2 bytes
	uint8_t key_with_checksum[KEY_MAX_LEN + 1] = { 0 };
	const int key_len = (nr_words * 11 - 1) / 8;
	const int checksum_len = (nr_words * 11) - (key_len * 8);

	if (nr_words != 12 && nr_words != 15 &&  nr_words != 18 &&
	    nr_words != 21 && nr_words != 24)
		return -1;

	for (i = 0; i < nr_words; i++) {
		bits = bip39_mnemonic_word_to_bits(words[i]);
		bits = u16_reverse_bits(bits) >> 5;
		mnemonic_bits[1] = (bits >> 8) & 0xff;
		mnemonic_bits[0] = bits & 0xff;
		bit_range_extract(key_with_checksum, 11 * i,
				  mnemonic_bits, 0, 11,
				  false);
	}
	for (i = 0; i < key_len + 1; i++)
		key_with_checksum[i] = u8_reverse_bits(key_with_checksum[i]);
	compute_sha256(key_with_checksum, key_len, digest);
	digest[0] &= bit_mask(checksum_len) << (8 - checksum_len);
	memcpy(key, key_with_checksum, key_len);
	*p_key_len = key_len;
	if (key_with_checksum[key_len] != digest[0])
		return -2;
	return 0;
}