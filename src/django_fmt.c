/* Django 1.4 patch for JtR. Hacked together during May of 2012 by
 * Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * Input Format => user:$django$*type*django-hash
 *
 * Where,
 *
 * type => 1, for Django 1.4 pbkdf_sha256 hashes and
 *
 * django-hash => Second column of "SELECT username, password FROM auth_user"
 *
 * July, 2012, the oSSL PKCS5_PBKDF2_HMAC function was replaced with a much faster
 * function pbkdf2() designed by JimF.  Originally this function was designed for
 * the mscash2 (DCC2).  The same pbkdf2 function, is used, and simply required small
 * changes to use SHA256.
 *
 * This new code is 3x to 4x FASTER than the original oSSL code. Even though it is
 * only useing oSSL functions.  A lot of the high level stuff in oSSL sux for speed.
 */


// uncomment this header to use the slower PKCS5_PBKDF2_HMAC function.
// Note, PKCS5_PBKDF2_HMAC is ONLY available in oSSL 1.00 + (1.0c I think to be exact)
//#include <openssl/evp.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "arch.h"
#include "sha2.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "base64.h"
#include "pbkdf2_hmac_sha256.h"
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               4 // tuned on core i7
static int omp_t = 1;
#endif
#include "memdbg.h"

#define FORMAT_LABEL		"django"
#define FORMAT_NAME		"Django PBKDF2-HMAC-SHA-256"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	" (x10000)"
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	64
#define HASH_LENGTH		44
#define BINARY_SIZE		32
#define SALT_SIZE		sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests django_tests[] = {
	{"$django$*1*pbkdf2_sha256$10000$qPmFbibfAY06$x/geVEkdZSlJMqvIYJ7G6i5l/6KJ0UpvLUU6cfj83VM=", "openwall"},
	{"$django$*1*pbkdf2_sha256$10000$BVmpZMBhRSd7$2nTDwPhSsDKOwpKiV04teVtf+a14Rs7na/lIB3KnHkM=", "123"},
	{"$django$*1*pbkdf2_sha256$10000$BVmpZMBhRSd1$bkdQo9RoatRomupPFP+XEo+Guuirq4mi+R1cFcV0U3M=", "openwall"},
	{"$django$*1*pbkdf2_sha256$10000$BVmpZMBhRSd6$Uq33DAHOFHUED+32IIqCqm+ITU1mhsGOJ7YwFf6h+6k=", "password"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static struct custom_salt {
	int type;
	int iterations;
	unsigned char salt[32];
} *cur_salt;

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	if (strncmp(ciphertext, "$django$*", 9) != 0)
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;;
	ctcopy += 9;
	if ((p = strtok(ctcopy, "*")) == NULL)	/* type */
		goto err;
	/* type must be 1 */
	if (atoi(p) != 1)
		goto err;
	if ((p = strtok(NULL, "$")) == NULL)	/* algorithm */
		goto err;
	if (strncmp(p, "pbkdf2_sha256", 13) != 0)
		goto err;
	if ((p = strtok(NULL, "$")) == NULL)	/* iterations */
		goto err;
	if ((p = strtok(NULL, "$")) == NULL)	/* hash */
		goto err;
	if (strlen(p) > HASH_LENGTH)
		goto err;
	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	char Buf[120], *ctcopy=Buf;
	char *p, *t;
	static struct custom_salt cs;
	memset(&cs, 0, sizeof(cs));
	strncpy(Buf, ciphertext, 119);
	Buf[119] = 0;
	ctcopy += 9;	/* skip over "$django$*" */
	p = strtok(ctcopy, "*");
	cs.type = atoi(p);
	p = strtok(NULL, "*");
	/* break up 'p' */
	strtok(p, "$");
	t = strtok(NULL, "$");
	cs.iterations = atoi(t);
	t = strtok(NULL, "$");
	strcpy((char*)cs.salt, t);

	return (void *)&cs;
}

static void *get_binary(char *ciphertext)
{	static union {
		unsigned char c[BINARY_SIZE+1];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	p = strrchr(ciphertext, '$') + 1;
	base64_decode(p, strlen(p), (char*)out);
	return out;
}

static int binary_hash_0(void *binary) { return *(ARCH_WORD_32 *)binary & 0xf; }
static int binary_hash_1(void *binary) { return *(ARCH_WORD_32 *)binary & 0xff; }
static int binary_hash_2(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfff; }
static int binary_hash_3(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffff; }
static int binary_hash_4(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfffff; }
static int binary_hash_5(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffffff; }
static int binary_hash_6(void *binary) { return *(ARCH_WORD_32 *)binary & 0x7ffffff; }

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
//		PKCS5_PBKDF2_HMAC(saved_key[index], strlen(saved_key[index]),
//			cur_salt->salt, strlen((char*)cur_salt->salt),
//			cur_salt->iterations, EVP_sha256(), 32, (unsigned char*)crypt_out[index]);

		pbkdf2_sha256((unsigned char *)saved_key[index], strlen(saved_key[index]),
			cur_salt->salt, strlen((char*)cur_salt->salt),
			cur_salt->iterations, crypt_out[index]);
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#ifdef _OPENMP
	for (; index < count; index++)
#endif
		if (!memcmp(binary, crypt_out[index], BINARY_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void django_set_key(char *key, int index)
{
	strcpy(saved_key[index], key);

}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_django = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		DEFAULT_ALIGN,
		SALT_SIZE,
		DEFAULT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		django_tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		fmt_default_source,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		fmt_default_salt_hash,
		set_salt,
		django_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};