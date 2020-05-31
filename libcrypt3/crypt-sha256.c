/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2011 The FreeBSD Project. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* Based on:
 * SHA256-based Unix crypt implementation. Released into the Public Domain by
 * Ulrich Drepper <drepper@redhat.com>. */

#include "internal3.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* Define our magic string to mark salt for SHA256 "encryption" replacement. */
static const char sha256_salt_prefix[] = "$5$";

/* Prefix for optional rounds specification. */
static const char sha256_rounds_prefix[] = "rounds=";

/* Maximum salt string length. */
#define SALT_LEN_MAX 16
/* Default number of rounds if not explicitly specified. */
#define ROUNDS_DEFAULT 5000
/* Minimum number of rounds. */
#define ROUNDS_MIN 1000
/* Maximum number of rounds. */
#define ROUNDS_MAX 999999999

int libcrypt3_sha256(const char *key, const char *salt, char *buffer) {
  unsigned long srounds;
  uint8_t alt_result[32], temp_result[32];
  SHA256_CTX ctx, alt_ctx;
  size_t salt_len, key_len, cnt, rounds;
  char *cp, *p_bytes, *s_bytes, *endp;
  const char *num;
  int rounds_custom;

  /* Default number of rounds. */
  rounds = ROUNDS_DEFAULT;
  rounds_custom = 0;

  /* Find beginning of salt string. The prefix should normally always
   * be present. Just in case it is not. */
  if(strncmp(sha256_salt_prefix, salt, sizeof(sha256_salt_prefix) - 1) == 0)
    /* Skip salt prefix. */
    salt += sizeof(sha256_salt_prefix) - 1;

  if(strncmp(salt, sha256_rounds_prefix, sizeof(sha256_rounds_prefix) - 1)
     == 0) {
    num = salt + sizeof(sha256_rounds_prefix) - 1;
    srounds = strtoul(num, &endp, 10);

    if(*endp == '$') {
      salt = endp + 1;
      rounds = MAX(ROUNDS_MIN, MIN(srounds, ROUNDS_MAX));
      rounds_custom = 1;
    }
  }

  salt_len = MIN(strcspn(salt, "$"), SALT_LEN_MAX);
  key_len = strlen(key);

  /* Prepare for the real work. */
  SHA256_Init(&ctx);

  /* Add the key string. */
  SHA256_Update(&ctx, key, key_len);

  /* The last part is the salt string. This must be at most 8
   * characters and it ends at the first `$' character (for
   * compatibility with existing implementations). */
  SHA256_Update(&ctx, salt, salt_len);

  /* Compute alternate SHA256 sum with input KEY, SALT, and KEY. The
   * final result will be added to the first context. */
  SHA256_Init(&alt_ctx);

  /* Add key. */
  SHA256_Update(&alt_ctx, key, key_len);

  /* Add salt. */
  SHA256_Update(&alt_ctx, salt, salt_len);

  /* Add key again. */
  SHA256_Update(&alt_ctx, key, key_len);

  /* Now get result of this (32 bytes) and add it to the other context. */
  SHA256_Final(alt_result, &alt_ctx);

  /* Add for any character in the key one byte of the alternate sum. */
  for(cnt = key_len; cnt > 32; cnt -= 32)
    SHA256_Update(&ctx, alt_result, 32);
  SHA256_Update(&ctx, alt_result, cnt);

  /* Take the binary representation of the length of the key and for
   * every 1 add the alternate sum, for every 0 the key. */
  for(cnt = key_len; cnt > 0; cnt >>= 1)
    if((cnt & 1) != 0)
      SHA256_Update(&ctx, alt_result, 32);
    else
      SHA256_Update(&ctx, key, key_len);

  /* Create intermediate result. */
  SHA256_Final(alt_result, &ctx);

  /* Start computation of P byte sequence. */
  SHA256_Init(&alt_ctx);

  /* For every character in the password add the entire password. */
  for(cnt = 0; cnt < key_len; ++cnt)
    SHA256_Update(&alt_ctx, key, key_len);

  /* Finish the digest. */
  SHA256_Final(temp_result, &alt_ctx);

  /* Create byte sequence P. */
  cp = p_bytes = alloca(key_len);
  for(cnt = key_len; cnt >= 32; cnt -= 32) {
    memcpy(cp, temp_result, 32);
    cp += 32;
  }
  memcpy(cp, temp_result, cnt);

  /* Start computation of S byte sequence. */
  SHA256_Init(&alt_ctx);

  /* For every character in the password add the entire password. */
  for(cnt = 0; cnt < 16u + alt_result[0]; ++cnt)
    SHA256_Update(&alt_ctx, salt, salt_len);

  /* Finish the digest. */
  SHA256_Final(temp_result, &alt_ctx);

  /* Create byte sequence S. */
  cp = s_bytes = alloca(salt_len);
  for(cnt = salt_len; cnt >= 32; cnt -= 32) {
    memcpy(cp, temp_result, 32);
    cp += 32;
  }
  memcpy(cp, temp_result, cnt);

  /* Repeatedly run the collected hash value through SHA256 to burn CPU
   * cycles. */
  for(cnt = 0; cnt < rounds; ++cnt) {
    /* New context. */
    SHA256_Init(&ctx);

    /* Add key or last result. */
    if((cnt & 1) != 0)
      SHA256_Update(&ctx, p_bytes, key_len);
    else
      SHA256_Update(&ctx, alt_result, 32);

    /* Add salt for numbers not divisible by 3. */
    if(cnt % 3 != 0)
      SHA256_Update(&ctx, s_bytes, salt_len);

    /* Add key for numbers not divisible by 7. */
    if(cnt % 7 != 0)
      SHA256_Update(&ctx, p_bytes, key_len);

    /* Add key or last result. */
    if((cnt & 1) != 0)
      SHA256_Update(&ctx, alt_result, 32);
    else
      SHA256_Update(&ctx, p_bytes, key_len);

    /* Create intermediate result. */
    SHA256_Final(alt_result, &ctx);
  }

  /* Now we can construct the result string. It consists of three
   * parts. */
  cp = stpcpy(buffer, sha256_salt_prefix);

  if(rounds_custom)
    cp += sprintf(cp, "%s%zu$", sha256_rounds_prefix, rounds);

  cp = stpncpy(cp, salt, salt_len);

  *cp++ = '$';

  libcrypt3_b64(alt_result[0], alt_result[10], alt_result[20], 4, &cp);
  libcrypt3_b64(alt_result[21], alt_result[1], alt_result[11], 4, &cp);
  libcrypt3_b64(alt_result[12], alt_result[22], alt_result[2], 4, &cp);
  libcrypt3_b64(alt_result[3], alt_result[13], alt_result[23], 4, &cp);
  libcrypt3_b64(alt_result[24], alt_result[4], alt_result[14], 4, &cp);
  libcrypt3_b64(alt_result[15], alt_result[25], alt_result[5], 4, &cp);
  libcrypt3_b64(alt_result[6], alt_result[16], alt_result[26], 4, &cp);
  libcrypt3_b64(alt_result[27], alt_result[7], alt_result[17], 4, &cp);
  libcrypt3_b64(alt_result[18], alt_result[28], alt_result[8], 4, &cp);
  libcrypt3_b64(alt_result[9], alt_result[19], alt_result[29], 4, &cp);
  libcrypt3_b64(0, alt_result[31], alt_result[30], 3, &cp);
  *cp = '\0'; /* Terminate the string. */

  /* Clear the buffer for the intermediate result so that people
   * attaching to processes or reading core dumps cannot get any
   * information.  */
  memset(temp_result, '\0', sizeof(temp_result));
  memset(p_bytes, '\0', key_len);
  memset(s_bytes, '\0', salt_len);

  return (0);
}
