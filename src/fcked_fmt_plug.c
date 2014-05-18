/* This software is Copyright (c) 2014, Dhiru Kholia <dhiru at openwall.com>
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted. */

#include <string.h>
#include <errno.h>
#ifdef _OPENMP
static int omp_t = 1;
#include <omp.h>
#define OMP_SCALE               64
#endif
#include "arch.h"
#include "md5.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include <openssl/sha.h>
#include <openssl/md4.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include "sph_md2.h"
#include "md2.h"

#define FORMAT_LABEL            "fcked"
#define FORMAT_NAME             "with crazy modes"
#define FORMAT_TAG              "$fcked$"
#define TAG_LENGTH              7
#define ALGORITHM_NAME          "32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             16
#define CIPHERTEXT_SIZE         32
#define SALT_SIZE               sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

static unsigned char *local_salt;
static int local_salt_length;

#ifdef DHIRU_FAVORITE_FUNCTION
static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
	printf("\n");
}
#endif

static int mode_in_algos(int mode)
{
	if (mode >=0 && mode <= 7) {
		return 1;
	}

	return 0;
}

static int mode_in_helpers(int mode)
{
	if (mode >=100 && mode <= 103) {
		return 1;
	}

	return 0;
}

static inline void hex_encode(unsigned char *str, int len, unsigned char *out)
{
	int i;
	for (i = 0; i < len; ++i) {
		out[0] = itoa16[str[i]>>4];
		out[1] = itoa16[str[i]&0xF];
		out += 2;
	}
}

static int hash(int mode, unsigned char *inout, int length)
{

	sph_md2_context m0;
	MD4_CTX         m1;
	MD5_CTX         m2;
	SHA_CTX         m3;
	SHA256_CTX      m4;
	SHA256_CTX      m5;
	SHA512_CTX      m6;
	SHA512_CTX      m7;

	switch(mode) {
		case 0:
			sph_md2_init(&m0);
			sph_md2(&m0, inout, length);
			sph_md2_close(&m0, inout);
			return 16;
		case 1:
			MD4_Init(&m1);
			MD4_Update(&m1, inout, length);
			MD4_Final(inout, &m1);
			return 16;
		case 2:
			MD5_Init(&m2);
			MD5_Update(&m2, inout, length);
			MD5_Final(inout, &m2);
			return 16;
		case 3:
			SHA1_Init(&m3);
			SHA1_Update(&m3, inout, length);
			SHA1_Final(inout, &m3);
			return 20;
		case 4:
			SHA224_Init(&m4);
			SHA224_Update(&m4, inout, length);
			SHA224_Final(inout, &m4);
			return 28;
		case 5:
			SHA256_Init(&m5);
			SHA256_Update(&m5, inout, length);
			SHA256_Final(inout, &m5);
			return 32;
		case 6:
			SHA384_Init(&m6);
			SHA384_Update(&m6, inout, length);
			SHA384_Final(inout, &m6);
			return 48;;
		case 7:
			SHA512_Init(&m7);
			SHA512_Update(&m7, inout, length);
			SHA512_Final(inout, &m7);
			return 64;
		default:
			printf("[!] Unexpected mode %d found!\n", mode);
			exit(-1);
	}
}


static void hash_hmac(char *salt, int salt_length, int mode, unsigned char *inout, unsigned int *length)
{
	HMAC_CTX ctx;
	unsigned char hexhash[128 + 1] = { 0 };
	const EVP_MD (*fptr);

	if (mode == 0) {
		/* HMAC-MD2 is "special" */
		md2_hmac((unsigned char*)salt, salt_length, inout, *length, inout);
		*length = 16;
	}
	else if (mode == 1)
		fptr = EVP_md4();
	else if (mode == 2)
		fptr = EVP_md5();
	else if (mode == 3)
		fptr = EVP_sha1();
	else if (mode == 4)
		fptr = EVP_sha224();
	else if (mode == 5)
		fptr = EVP_sha256();
	else if (mode == 6)
		fptr = EVP_sha224();
	else if (mode == 7)
		fptr = EVP_sha512();
	else {
		printf("[!] Unexpected mode %d found!\n", mode);
		exit(-1);
	}

	if (mode != 0) {
		HMAC_CTX_init(&ctx);
		HMAC_Init_ex(&ctx, (unsigned char*)salt, salt_length, fptr, NULL);
		HMAC_Update(&ctx, inout, *length);
		HMAC_Final(&ctx, inout, length);
		HMAC_CTX_cleanup(&ctx);
	}

	/* always hex-encode */
	hex_encode(inout, *length, hexhash);
	*length = *length * 2;
	memcpy(inout, hexhash, *length);
}

static int helpers(unsigned char *password, int mode, unsigned int length)
{
	if (mode == 100) {
		// do base64 encoding
		BIO *b64, *mem;
		char* b64_data;
		long len;
		b64 = BIO_new(BIO_f_base64());
		BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
		mem = BIO_new(BIO_s_mem());
		BIO_push(b64, mem);
		BIO_write(b64, password, length);
		BIO_flush(b64);
		len = BIO_get_mem_data(mem, &b64_data);
		strncpy((char*)password, b64_data, len);
		BIO_free_all(b64);
		return len;
	}
	else if (mode == 101) {
		unsigned char hexhash[512] = { 0 };
		hex_encode(password, length, hexhash);
		memcpy(password, hexhash, length * 2);
		return length * 2;
	}
	else if (mode == 102) {
		// string reverse
		int i, j;
		unsigned char tmp;
		for (i = 0, j = length - 1; i < j; i++, j--) {
			tmp = password[i];
			password[i] = password[j];
			password[j] = tmp;
		}
		return length;
	}
	else if (mode == 103) {
		int i;
		for (i = 0; i < length; i++) {
			password[i + length] = password[i];
		}
		return length * 2;
	}
	else {
		printf("[!] Unexpected mode %d found!\n", mode);
		exit(-1);
	}

	return -1;
}

static int hash_step(char *salt, int mode, unsigned char *inout, unsigned int length)
{
	if (mode_in_algos(mode)) {
		return hash(mode, inout, length);  // "inout" is "raw" (not hex-encoded)
	} else if (mode_in_algos(mode - 10)) { // e.g. 10
		hash_hmac(salt, strlen(salt), mode - 10, inout, &length);
	} else if (mode_in_algos(mode - 20)) {
		// "local_salt" mode
		hash_hmac((char*)local_salt, local_salt_length,  mode - 20, inout, &length);
	} else if (mode_in_helpers(mode)) {
		return helpers(inout, mode, length);
	} else {
		exit(-1);
	}

	return length;
}


static void do_hash(char *password, char *salt, int modes[], int n, unsigned char *inout)
{

	int i;
	int mode;
	MD5_CTX ctx;

	int current_length = strlen(password);
	strncpy((char*)inout, password, PLAINTEXT_LENGTH);

	for (i = 0; i < n; i++) {
		mode = modes[i];
		// printf("[>] looping for mode %d with password %s\n", mode, password);
		current_length = hash_step(salt, mode, inout, current_length);
		// print_hex(inout, current_length);
	}

	/* always do 1 iteration of MD5 */
	MD5_Init(&ctx);
	MD5_Update(&ctx, inout, current_length);
	MD5_Final(inout, &ctx);
}

static struct fmt_tests tests[] = {
	// do_hash("password", "salt", "0,1,2,10,20,101,102");  # "local_salt"
	//{"$salt$0,1,2,10,20,101,102$1d66d5f4b411be3b4eafc03e04276cb9", "password"},

	// do_hash("password", "salt", "1");
	//{"$salt$1$859c46324bb144d68a1a2a74dc653771", "password"},
	// echo do_hash("password", "salt", "1,2");
	//{"$salt$1,2$2e13e1b2a4cc59736340762b0b4613f3", "password"},
	// do_hash("password", "salt", "0,1,2,3");
	{"$salt$0,1,2,3$a11c5ff654eefe1edbe42fa2b4544bd4", "password"},
	// do_hash("password", "salt", "0,1,2,4");
	//{"$salt$0,1,2,4$c5300c5fe7757360313437afccd6a5f8", "password"},

	// do_hash("password", "salt", "0,1,2,10");
	//{"$salt$0,1,2,10$163732b5d61539781c0e88eb308d8313", "password"},

	// do_hash("password", "salt", "101,11,17,1");
	//{"$salt$101,11,17,1$d36a3e8ff20165bf877de05a8adb3063", "password"},

	// do_hash("password@123456789", "salt", "13,10,100,1");
	//{"$salt$13,10,100,1$8c481ea9576968f94a2cc96dae9b3c76", "password@123456789"},

	// do_hash("password@123456789", "salt", "3,6,12,3");
	//{"$salt$3,6,12,3$45891f3cdd5348a4773fa057d6b7909e", "password@123456789"},

	// do_hash("password@1234567890", "salt", "14,11,2,12");
	{"$salt$14,11,2,12$5a1afb1075322cc79e44f86fec7ad056", "password@1234567890"},

	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];

// PLAINTEXT_LENGTH * 2 is done to handle all the string doubling and other crazy operations!
static ARCH_WORD_32 (*crypt_out)[PLAINTEXT_LENGTH * 2 + sizeof(ARCH_WORD_32) / sizeof(ARCH_WORD_32)];

static void init(struct fmt_main *self)
{
	FILE *fp;
	long pos;
	size_t read;
#ifdef _OPENMP
	int omp_t = omp_get_num_threads();

	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
		self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);

	/* load "salt.txt" file into "local_salt" */
	fp = fopen("salt.txt", "rb");
	if (!fp) {
		fprintf(stderr, "[-] unable to load salt.txt file, exiting now!\n");
		exit(-1);
	}

	fseek(fp, 0, SEEK_END);
	pos = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	local_salt = (unsigned char*)malloc(pos);
	local_salt_length = pos;
	read =fread(local_salt, 1, pos, fp);
	fprintf(stderr, "[+] read %ld / %ld bytes from salt.txt file!\n", read, pos);
	fclose(fp);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *start, *q, *r;
	int hash_length;
	int mode;
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;

	p = ciphertext;

	if (!strncmp(p, FORMAT_TAG, TAG_LENGTH))
		p += TAG_LENGTH;

	start = strrchr(ciphertext, '$');
	if (!start)
		return 0;
	hash_length = strlen(start + 1);
	if (hash_length != CIPHERTEXT_SIZE)
		return 0;

	// validates modes
	if (!strncmp(ctcopy, FORMAT_TAG, TAG_LENGTH))
		ctcopy += TAG_LENGTH;
	p = ctcopy + 1;
	q = strchr(p, '$');

	p = q + 1;
	q = strchr(p, '$');

	/* split modes */
        r = strtok(p, ",");
	mode = atoi(r);
	while (1) {
		r = strtok(NULL, ",");
		if (!r)
			break;
		mode = atoi(r);
		if (mode_in_algos(mode)) {
		} else if (mode_in_algos(mode - 10)) { // e.g. 10
		} else if (mode_in_algos(mode - 20) && !local_salt) {
			// printf("[-] rejecting %s due to local_salt mode!\n", ciphertext);
			// free(keeptr);
			//return 0;
		}
	}

	free(keeptr);
	return 1;
}


static struct custom_salt {
	int length;
	char salt[16];
	int modes[32];
	int n;
} *cur_salt;

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *p, *q, *r;

	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;

	memset(&cs, 0, SALT_SIZE);

	if (!strncmp(ctcopy, FORMAT_TAG, TAG_LENGTH))
		ctcopy += TAG_LENGTH;

	p = ctcopy + 1;
	q = strchr(p, '$');
	strncpy(cs.salt, p, q - p);

	p = q + 1;
	q = strchr(p, '$');

	/* split modes */
        r = strtok(p, ",");
	cs.modes[cs.n] = atoi(r);
	cs.n++;
	while (1) {
		r = strtok(NULL, ",");
		if (!r)
			break;
		cs.modes[cs.n] = atoi(r);
		cs.n++;
	}

	free(keeptr);
	return &cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;
	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

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
#endif
#if defined(_OPENMP) || MAX_KEYS_PER_CRYPT > 1
	for (index = 0; index < count; index++)
#endif
	{
		do_hash(saved_key[index], cur_salt->salt, cur_salt->modes,
				cur_salt->n, (unsigned char*)crypt_out[index]);
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#ifdef _OPENMP
	for (; index < count; index++)
#endif
		if (((ARCH_WORD_32*)binary)[0] == crypt_out[index][0])
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

static void set_key(char *key, int index)
{
	int saved_key_length = strlen(key);

	if (saved_key_length > PLAINTEXT_LENGTH)
		saved_key_length = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_key_length);
	saved_key[index][saved_key_length] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_fcked = {
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
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		tests,
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		fmt_default_source,
		{
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		fmt_default_salt_hash,
		set_salt,
		set_key,
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
