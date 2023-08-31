/*
 * Copyright (c) 2023 Siddharth Chandrasekaran <sidcha.dev@gmail.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _BIP_39_H_
#define _BIP_39_H_

#include <stdint.h>

#define KEY_MAX_LEN 32
#define MS_MAX_WORDS 24

const char *bip39_word_is_valid(const char *word);

int bip39_key_to_mnemonic_words(const uint8_t *key, const int key_len,
				const char *words[MS_MAX_WORDS], int *nr_words);

int bip39_key_from_mnemonic_words(const char *words[MS_MAX_WORDS], int nr_words,
				  uint8_t key[KEY_MAX_LEN], int *key_len);

#endif /* _BIP_39_H_ */