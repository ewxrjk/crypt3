/* LINTLIBRARY */
/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 1999
 *      Mark Murray.  All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY MARK MURRAY AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL MARK MURRAY OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: head/lib/libcrypt/crypt.h 326219 2017-11-26 02:00:33Z pfg $
 *
 */
#ifndef LIBCRYPT3_H
#define LIBCRYPT3_H

/** @file libcrypt3.h
 * @brief Traditional password encryption
 *
 * These functions provide access to the password encryption algorithms
 * provided by crypt(3) on some platforms.
 */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief State structured used by @ref libcrypt3_crypt_r */
struct libcrypt3_data {
  /** @brief Buffer returned by @ref libcrypt3_crypt_r */
  char buf[256];
};

/** @brief The set of characters that may be used in a password salt */
#define LIBCRYPT3_ALPHABET                                                     \
  "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

/** @brief Non-re-entrant Password encryption
 * @param passwd The password to encrypt
 * @param salt The salt string, or the encrytped password
 * @return A private copy of the encrypted password
 *
 * This function is equivalent to @ref libcrypt3_crypt_r,
 * except that it uses a private internal buffer.
 * This means that:
 * - it must not be called concurrently from two threads.
 * - each call will overwrite the value returned by the previuos call.
 */
char *libcrypt3_crypt(const char *passwd, const char *salt);

/** @brief Re-entrant password encryption
 * @param passwd The password to encrypt
 * @param salt The salt string, or the encrypted password
 * @param data A buffer for the result
 * @return The encrypted password
 *
 * The algorithm used depends on the @p salt parameter:
 *
 * Salt Format            | Primitive | Salt Length | Rounds
 * -----------------------|-----------|-------------|--------
 * @c SALT                | DES       | 2           | 25
 * @c $1$SALT[$]          | MD5       | 8           | 1000
 * @c $5$SALT[$]          | SHA256    | 16          | 5000
 * @c $5$rounds=N$SALT[$] | SHA256    | 16          | N
 * @c $6$                 | SHA512    | 16          | 5000
 * @c $6$rounds=N$SALT[$] | SHA512    | 16          | N
 *
 * In all cases:
 * - The salt must be picked at random from the characters in @ref
 * LIBCRYPT3_ALPHABET.
 * - Any salt characters beyond the salt length are ignored.
 * - Fresh salt must be picked every time a password is encrypted.
 *
 * @ref libcrypt3_pick_salt can be used to pick a suitable salt value.
 *
 * **MD5 Encryption**
 *
 * The password and the salt are encrypted repeatedly using MD5.
 * The result has the format @c $1$SALT$CIPHERTEXT.
 *
 * **SHA256 and SHA512 Encryption**
 *
 * The password and the salt are encrypted repeatedly using SHA256 or SHA512.
 * The result has the format @c $5$SALT$CIPHERTEXT or  @c
 * $5$rounds=N$SALT$CIPHERTEXT (and similarly for SHA512, with @c $6$).
 *
 * **DES Encryption**
 *
 * The password and the salt are encrypted using an iterated DES variant.
 * The result has the format SALT || CIPHERTEXT.
 *
 * Note that:
 * - DES encryption only considers the first 8 bytes of the password
 * - DES encryption ignores bit 7 of each byte of the password
 */
char *libcrypt3_crypt_r(const char *passwd, const char *salt,
                        struct libcrypt3_data *data);

/** @brief Create salt for the legacy DES-based password encryption algorithm */
#define LIBCRYPT3_DES 0

/** @brief Create salt for the MD5-based password encryption algorithm */
#define LIBCRYPT3_MD5 1

/** @brief Create salt for the SHA256-based password encryption algorithm */
#define LIBCRYPT3_SHA256 5

/** @brief Create salt for the SHA512-based password encryption algorithm */
#define LIBCRYPT3_SHA512 6

/** @brief Pick a random salt for @ref libcrypt3_crypt or @ref libcrypt3_crypt_r
 * @param buffer Buffer for result
 * @param bufsize Size of buffer
 * @param alg Algorithm to use for password encryption
 * @param rounds Number of rounds to request
 * @return Negative on error, non-negative on success
 *
 * No more than @p bufsize characters will be written to @p buffer, including
 * a 0 terminator.
 *
 * @p alg should be one of @@ref LIBCRYPT3_DES, @ref
 * LIBCRYPT3_MD5, @ref LIBCRYPT3_SHA256 or @ref LIBCRYPT3_SHA512.
 *
 * @p rounds should be 0 to select the default or any positive value to select
 * a non-default round count. The latter only works for @ref LIBCRYPT3_SHA256
 * and @ref LIBCRYPT3_SHA512.
 */
int libcrypt3_pick_salt(char buffer[], size_t bufsize, int alg, int rounds);

#ifdef __cplusplus
}
#endif

#endif
