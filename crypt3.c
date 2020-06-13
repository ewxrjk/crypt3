/*
 * This file is part of crypt3.
 * Copyright © Richard Kettlewell
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <config.h>

#include "libcrypt3.h"

enum {
  OPT_HELP = UCHAR_MAX + 1,
  OPT_VERSION,
  OPT_ROUNDS,
  OPT_NATIVE,

  OPT_ALG,
  OPT_DES = OPT_ALG + LIBCRYPT3_DES,
  OPT_MD5 = OPT_ALG + LIBCRYPT3_MD5,
  OPT_SHA256 = OPT_ALG + LIBCRYPT3_SHA256,
  OPT_SHA512 = OPT_ALG + LIBCRYPT3_SHA512,
};

static int alg = LIBCRYPT3_SHA512;
static int rounds = 0;
static int native = 0;

static const struct option options[] = {
  { "help", no_argument, NULL, OPT_HELP },
  { "version", no_argument, NULL, OPT_VERSION },
  { "rounds", required_argument, NULL, OPT_ROUNDS },
  { "native", no_argument, NULL, OPT_NATIVE },
  { "des", no_argument, NULL, OPT_DES },
  { "md5", no_argument, NULL, OPT_MD5 },
  { "sha256", no_argument, NULL, OPT_SHA256 },
  { "sha512", no_argument, NULL, OPT_SHA512 },
  { NULL, 0, NULL, 0 },
};

static void help(void) {
  printf("crypt3 -- encrypt passwords\n"
         "\n"
         "Usage:\n"
         "  crypt3 [OPTIONS] [--] [PASSWORD ...]\n"
         "Mode options:\n"
         "  --des                      DES (comedically insecure)\n"
         "  --md5                      MD5\n"
         "  --sha256                   SHA256\n"
         "  --sha512                   SHA512 (default)\n"
         "Other options:\n"
         "  --help                     Display usage message\n"
         "  --version                  Display version string\n");
}

#ifndef TAG
#define TAG "unknown"
#endif

static void version(void) {
  printf("version %s tag %s\n", PACKAGE_VERSION, TAG);
}

static void encrypt(char buffer[], size_t bufsize, const char *pw) {
  char salt[64];
  if(libcrypt3_pick_salt(salt, sizeof salt, alg, rounds) < 0) {
    perror("picking salt");
    exit(1);
  }
  if(native) {
    const char *encrypted = crypt(pw, salt);
    if(!encrypted || strlen(encrypted) >= bufsize) {
      perror("password encryption failed");
      exit(1);
    }
    strcpy(buffer, encrypted);
  } else {
    if(!libcrypt3_crypt(buffer, bufsize, pw, salt)) {
      perror("password encryption failed");
      exit(1);
    }
  }
}

static void getpass_buffer(char buffer[], size_t bufsize, const char *prompt) {
  for(;;) {
    const char *pw = getpass(prompt);
    if(strlen(pw) >= bufsize) {
      fprintf(stderr, "Password too long\n");
      continue;
    }
    strcpy(buffer, pw);
    return;
  }
}

static int encrypt_getpass(void) {
  char pw1[1024], pw2[1024];
  char buffer[LIBCRYPT3_BUFSIZE];

  for(;;) {
    getpass_buffer(pw1, sizeof pw1, "Enter password: ");
    getpass_buffer(pw2, sizeof pw2, "Retype password: ");
    if(!strcmp(pw1, pw2))
      break;
    fprintf(stderr, "ERROR: passwords do not match\n");
  }
  encrypt(buffer, sizeof buffer, pw1);
  return printf("%s\n", buffer) < 0;
}

static int encrypt_stdin(void) {
  char line[4096];
  char buffer[LIBCRYPT3_BUFSIZE];
  for(;;) {
    int ch;
    size_t pos = 0;

    while((ch = getchar()) != EOF && ch != '\n') {
      if(pos >= sizeof line - 1) {
        fprintf(stderr, "ERROR: line too long\n");
        exit(1);
      }
      line[pos++] = ch;
    }
    line[pos] = 0;
    if(ch == EOF) {
      if(ferror(stdin)) {
        perror("stdin");
        return 1;
      }
      return 0;
    }
    encrypt(buffer, sizeof buffer, line);
    if(printf("%s\n", buffer) < 0)
      return 1;
  }
}

int main(int argc, char **argv) {
  int n;
  while((n = getopt_long(argc, argv, "", options, NULL)) >= 0) {
    switch(n) {
    case OPT_HELP: help(); return 0;
    case OPT_VERSION: version(); return 0;
    case OPT_ROUNDS: rounds = atoi(optarg); break;
    case OPT_NATIVE: native = 1; break;
    case OPT_DES:
    case OPT_MD5:
    case OPT_SHA256:
    case OPT_SHA512: alg = n - OPT_ALG; break;
    default: return 1;
    }
  }
  if(optind == argc) {
    if(isatty(0)) {
      if(encrypt_getpass())
        return 1;
    } else {
      if(encrypt_stdin())
        return 1;
    }
  } else {
    char buffer[LIBCRYPT3_BUFSIZE];
    for(n = optind; n < argc; n++) {
      encrypt(buffer, sizeof buffer, argv[n]);
      printf("%s\n", buffer);
    }
  }
  if(fflush(stdout) < 0 || ferror(stdout)) {
    perror("stdout");
    return 1;
  }
  return 0;
}
