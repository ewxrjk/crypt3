/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2003 Poul-Henning Kamp
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

#include "internal3.h"

#include <string.h>

#define MD5_SIZE 16

/*
 * UNIX password
 */

int libcrypt3_md5(char *buffer, size_t attribute((unused)) bufsize,
                  const char *pw, const char *salt) {
  MD5_CTX ctx, ctx1;
  unsigned long l;
  int sl, pl;
  unsigned int i;
  unsigned char final[MD5_SIZE];
  const char *ep;
  static const char *magic = "$1$";

  /* If the salt starts with the magic string, skip that. */
  if(!strncmp(salt, magic, strlen(magic)))
    salt += strlen(magic);

  /* It stops at the first '$', max 8 chars */
  for(ep = salt; *ep && *ep != '$' && ep < salt + 8; ep++)
    continue;

  /* get the length of the true salt */
  sl = ep - salt;

  MD5_Init(&ctx);

  /* The password first, since that is what is most unknown */
  MD5_Update(&ctx, (const unsigned char *)pw, strlen(pw));

  /* Then our magic string */
  MD5_Update(&ctx, (const unsigned char *)magic, strlen(magic));

  /* Then the raw salt */
  MD5_Update(&ctx, (const unsigned char *)salt, (unsigned)sl);

  /* Then just as many characters of the MD5(pw,salt,pw) */
  MD5_Init(&ctx1);
  MD5_Update(&ctx1, (const unsigned char *)pw, strlen(pw));
  MD5_Update(&ctx1, (const unsigned char *)salt, (unsigned)sl);
  MD5_Update(&ctx1, (const unsigned char *)pw, strlen(pw));
  MD5_Final(final, &ctx1);
  for(pl = (int)strlen(pw); pl > 0; pl -= MD5_SIZE)
    MD5_Update(&ctx, (const unsigned char *)final,
               (unsigned)(pl > MD5_SIZE ? MD5_SIZE : pl));

  /* Don't leave anything around in vm they could use. */
  memset(final, 0, sizeof(final));

  /* Then something really weird... */
  for(i = strlen(pw); i; i >>= 1)
    if(i & 1)
      MD5_Update(&ctx, (const unsigned char *)final, 1);
    else
      MD5_Update(&ctx, (const unsigned char *)pw, 1);

  /* Now make the output string */
  buffer = stpcpy(buffer, magic);
  buffer = stpncpy(buffer, salt, (unsigned)sl);
  *buffer++ = '$';

  MD5_Final(final, &ctx);

  /*
   * and now, just to make sure things don't run too fast
   * On a 60 Mhz Pentium this takes 34 msec, so you would
   * need 30 seconds to build a 1000 entry dictionary...
   */
  for(i = 0; i < 1000; i++) {
    MD5_Init(&ctx1);
    if(i & 1)
      MD5_Update(&ctx1, (const unsigned char *)pw, strlen(pw));
    else
      MD5_Update(&ctx1, (const unsigned char *)final, MD5_SIZE);

    if(i % 3)
      MD5_Update(&ctx1, (const unsigned char *)salt, (unsigned)sl);

    if(i % 7)
      MD5_Update(&ctx1, (const unsigned char *)pw, strlen(pw));

    if(i & 1)
      MD5_Update(&ctx1, (const unsigned char *)final, MD5_SIZE);
    else
      MD5_Update(&ctx1, (const unsigned char *)pw, strlen(pw));
    MD5_Final(final, &ctx1);
  }

  l = (final[0] << 16) | (final[6] << 8) | final[12];
  libcrypt3_to64(buffer, l, 4);
  buffer += 4;
  l = (final[1] << 16) | (final[7] << 8) | final[13];
  libcrypt3_to64(buffer, l, 4);
  buffer += 4;
  l = (final[2] << 16) | (final[8] << 8) | final[14];
  libcrypt3_to64(buffer, l, 4);
  buffer += 4;
  l = (final[3] << 16) | (final[9] << 8) | final[15];
  libcrypt3_to64(buffer, l, 4);
  buffer += 4;
  l = (final[4] << 16) | (final[10] << 8) | final[5];
  libcrypt3_to64(buffer, l, 4);
  buffer += 4;
  l = final[11];
  libcrypt3_to64(buffer, l, 2);
  buffer += 2;
  *buffer = '\0';

  /* Don't leave anything around in vm they could use. */
  memset(final, 0, sizeof(final));

  return (0);
}
