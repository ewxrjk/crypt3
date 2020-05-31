/*
 * This file is part of crypt3.
 * Copyright © Richard Kettlewell
 * Copyright (c) 1999 Mark Murray.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of other contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 */
#ifndef INTERNAL3_H
#define INTERNAL3_H

#include "libcrypt3.h"

#include <stdint.h>

int libcrypt3_des(const char *pw, const char *salt, char *buf);
int libcrypt3_md5(const char *pw, const char *salt, char *buf);
int libcrypt3_nthash(const char *pw, const char *salt, char *buf);
int libcrypt3_blowfish(const char *pw, const char *salt, char *buf);
int libcrypt3_sha256(const char *pw, const char *salt, char *buf);
int libcrypt3_sha512(const char *pw, const char *salt, char *buf);

extern void libcrypt3_to64(char *s, unsigned long v, int n);
extern void libcrypt3_b64(uint8_t B2, uint8_t B1, uint8_t B0, int n, char **cp);

#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))

#if __APPLE__

#include <CommonCrypto/CommonDigest.h>

#define MD5_CTX CC_MD5_CTX
#define MD5_Init CC_MD5_Init
#define MD5_Update CC_MD5_Update
#define MD5_Final CC_MD5_Final

#define SHA256_CTX CC_SHA256_CTX
#define SHA256_Init CC_SHA256_Init
#define SHA256_Update CC_SHA256_Update
#define SHA256_Final CC_SHA256_Final

#define SHA512_CTX CC_SHA512_CTX
#define SHA512_Init CC_SHA512_Init
#define SHA512_Update CC_SHA512_Update
#define SHA512_Final CC_SHA512_Final

#else

#include <openssl/md5.h>
#include <openssl/sha.h>

#endif

#endif
