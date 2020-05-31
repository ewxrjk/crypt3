/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 1999 Mark Murray
 * Copyright (c) 2014 Dag-Erling Smørgrav
 * All rights reserved.
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
 */

#include "internal3.h"

#include <string.h>
#include <unistd.h>

/*
 * List of supported crypt(3) formats.
 *
 * The default algorithm is the last entry in the list (second-to-last
 * array element since the last is a sentinel).  The reason for placing
 * the default last rather than first is that DES needs to be at the
 * bottom for the algorithm guessing logic in crypt(3) to work correctly,
 * and it needs to be the default for backward compatibility.
 */
static const struct crypt_format {
  const char *name;
  int (*func)(const char *, const char *, char *);
  const char *magic;
} crypt_formats[] = { { "md5", libcrypt3_md5, "$1$" },
                      { "sha256", libcrypt3_sha256, "$5$" },
                      { "sha512", libcrypt3_sha512, "$6$" },
                      { "des", libcrypt3_des, "_" },
                      /* sentinel */
                      { NULL, NULL, NULL } };

static const struct crypt_format *crypt_format =
  &crypt_formats[(sizeof crypt_formats / sizeof *crypt_formats) - 2];

#define DES_SALT_ALPHABET                                                      \
  "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

/*
 * Returns the name of the currently selected format.
 */
const char *crypt_get_format(void) {

  return (crypt_format->name);
}

/*
 * Selects the format to use for subsequent crypt(3) invocations.
 */
int crypt_set_format(const char *format) {
  const struct crypt_format *cf;

  for(cf = crypt_formats; cf->name != NULL; ++cf) {
    if(strcasecmp(cf->name, format) == 0) {
      crypt_format = cf;
      return (1);
    }
  }
  return (0);
}

/*
 * Hash the given password with the given salt.  If the salt begins with a
 * magic string (e.g. "$6$" for sha512), the corresponding format is used;
 * otherwise, the currently selected format is used.
 */
char *libcrypt3_crypt_r(const char *passwd, const char *salt,
                        struct libcrypt3_data *data) {
  const struct crypt_format *cf;
  int (*func)(const char *, const char *, char *);
#ifdef HAS_DES
  int len;
#endif

  for(cf = crypt_formats; cf->name != NULL; ++cf)
    if(cf->magic != NULL && strstr(salt, cf->magic) == salt) {
      func = cf->func;
      goto match;
    }
#ifdef HAS_DES
  len = strlen(salt);
  if((len == 13 || len == 2) && strspn(salt, DES_SALT_ALPHABET) == len) {
    func = crypt_des;
    goto match;
  }
#endif
  func = crypt_format->func;
match:
  if(func(passwd, salt, data->buf) != 0)
    return (NULL);
  return (data->buf);
}

char *libcrypt3_crypt(const char *passwd, const char *salt) {
  static struct libcrypt3_data data;

  return (libcrypt3_crypt_r(passwd, salt, &data));
}
