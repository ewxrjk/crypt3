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
#include <cstdio>
#include <climits>
#include <cstdlib>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <string>
#include <algorithm>
#include <config.h>

#include "libcrypt3.h"

enum {
  OPT_HELP = UCHAR_MAX + 1,
  OPT_VERSION,
  OPT_ROUNDS,
  OPT_ALG,
  OPT_DES = OPT_ALG + LIBCRYPT3_DES,
  OPT_MD5 = OPT_ALG + LIBCRYPT3_MD5,
  OPT_SHA256 = OPT_ALG + LIBCRYPT3_SHA256,
  OPT_SHA512 = OPT_ALG + LIBCRYPT3_SHA512,
};

static int alg = LIBCRYPT3_SHA512;
static int rounds = 0;

static const struct option options[] = {
  { "help", no_argument, nullptr, OPT_HELP },
  { "version", no_argument, nullptr, OPT_VERSION },
  { "rounds", required_argument, nullptr, OPT_ROUNDS },
  { "des", no_argument, nullptr, OPT_DES },
  { "md5", no_argument, nullptr, OPT_MD5 },
  { "sha256", no_argument, nullptr, OPT_SHA256 },
  { "sha512", no_argument, nullptr, OPT_SHA512 },
  { nullptr, 0, nullptr, 0 },
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

static std::string encrypt(const std::string pw) {
  char salt[64];
  char buffer[LIBCRYPT3_BUFSIZE];
  if(libcrypt3_pick_salt(salt, sizeof salt, alg, 0) < 0) {
    perror("picking salt");
    exit(1);
  }
  return libcrypt3_crypt(buffer, sizeof buffer, pw.c_str(), salt);
}

static int encrypt_getpass(void) {
  std::string pw1, pw2;

  for(;;) {
    pw1 = getpass("Enter password: ");
    pw2 = getpass("Retype password: ");
    if(pw1 == pw2)
      break;
    fprintf(stderr, "ERROR: passwords do not match\n");
  }
  return printf("%s\n", encrypt(pw1).c_str()) < 0;
}

static int encrypt_stdin(void) {
  std::string s;
  for(;;) {
    int ch;

    s.clear();
    while((ch = getchar()) != EOF && ch != '\n')
      s += (char)ch;
    if(ch == EOF) {
      if(ferror(stdin)) {
        perror("stdin");
        return 1;
      }
      return 0;
    }
    if(printf("%s\n", encrypt(s).c_str()) < 0)
      return 1;
  }
}

int main(int argc, char **argv) {
  int n;
  while((n = getopt_long(argc, argv, "", options, nullptr)) >= 0) {
    switch(n) {
    case OPT_HELP: help(); return 0;
    case OPT_VERSION: version(); return 0;
    case OPT_ROUNDS: rounds = atoi(optarg); break;
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
    for(n = optind; n < argc; n++)
      printf("%s\n", encrypt(argv[n]).c_str());
  }
  if(fflush(stdout) < 0 || ferror(stdout)) {
    perror("stdout");
    return 1;
  }
  return 0;
}
