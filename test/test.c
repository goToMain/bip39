/*
 * Copyright (c) 2023 Siddharth Chandrasekaran <sidcha.dev@gmail.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include "bip39.h"
#include "test.h"

void print_words(const char *head, const char *words[], size_t nr_words)
{
	int i;
	printf("%s", head);
	for (i = 0; i < nr_words; i++)
		printf("%s ", words[i]);
	printf("\n");
}

int test_bip39_key_to_words(struct bip39_test_vector *vec)
{
	int rc, i = 0, nr_words;
	const char *words[MS_MAX_WORDS];

	rc = bip39_key_to_mnemonic_words(vec->key, vec->key_len, words, &nr_words);
	if (rc)
		return rc;

	if (vec->nr_words != nr_words)
		return -3;

	for (i = 0; i < vec->nr_words; i++)
		if (strcmp(words[i], vec->words[i]) != 0)
			return -4;
	return 0;
}

int test_bip39_words_to_key(struct bip39_test_vector *vec)
{
	int rc, i = 0;
	int key_len;
	uint8_t key[KEY_MAX_LEN];

	rc = bip39_key_from_mnemonic_words(vec->words, vec->nr_words, key, &key_len);
	if (rc)
		return rc;

	if (vec->key_len != key_len)
		return -3;

	for (i = 0; i < key_len; i++)
		if (memcmp(vec->key, key, key_len) != 0)
			return -4;
	return 0;
}

int main()
{
	int rc, i;

	for (i = 0; i < ARRAY_SIZEOF(bip39_test_vectors); i++) {
		if ((rc = test_bip39_key_to_words(&bip39_test_vectors[i])) != 0) {
			printf("bip39_key_to_words: test %d failed! rc:%d\n", i, rc);
			return -1;
		}
		if ((rc = test_bip39_words_to_key(&bip39_test_vectors[i])) != 0) {
			printf("bip39_words_to_key: test %d failed! rc:%d\n", i, rc);
			return -1;
		}
	}

	printf("Test OK!\n");
	return 0;
}
