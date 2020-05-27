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

enum {
  OPT_HELP = UCHAR_MAX + 1,
  OPT_VERSION,
  OPT_DES,
  OPT_MD5,
  OPT_SHA256,
  OPT_SHA512,
};

static int alg = OPT_SHA512;
static int randomfd = -1;

static const struct option options[] = {
  { "help", no_argument, nullptr, OPT_HELP },
  { "version", no_argument, nullptr, OPT_VERSION },
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

static void version(void) {
  printf("version %s tag %s\n", PACKAGE_VERSION, TAG);
}

static std::string getsalt(size_t n) {
  static const char saltchars[] =
    "abcdefghijklmnopqrstvuwxyzABCDEFGHIJKLMNOPQRSTUVWXTZ0123456789./";
  std::string s;
  char buffer[64];
  if(randomfd < 0) {
    if((randomfd = open("/dev/urandom", O_RDONLY)) < 0) {
      perror("/dev/urandom");
      exit(1);
    }
  }
  while(s.size() < n) {
    ssize_t r = read(randomfd, buffer, std::min(sizeof buffer, n - s.size()));
    if(r < 0) {
      perror("read /dev/urandom");
      exit(1);
    }
    s.append(buffer, r);
  }
  for(size_t i = 0; i < n; i++)
    s.at(i) = saltchars[s.at(i) & 63];
  return s;
}

static std::string encrypt(const std::string pw) {
  std::string salt;
  switch(alg) {
  case OPT_DES: salt = getsalt(2); break;
  case OPT_MD5: salt = "$1$" + getsalt(22); break;
  case OPT_SHA256: salt = "$5$" + getsalt(43); break;
  case OPT_SHA512: salt = "$6$" + getsalt(86); break;
  default: abort(); // shouldn't happen
  }
  return crypt(pw.c_str(), salt.c_str());
}

int main(int argc, char **argv) {
  int n;
  while((n = getopt_long(argc, argv, "", options, nullptr)) >= 0) {
    switch(n) {
    case OPT_HELP: help(); return 0;
    case OPT_VERSION: version(); return 0;
    case OPT_DES:
    case OPT_MD5:
    case OPT_SHA256:
    case OPT_SHA512: alg = n; break;
    default: return 1;
    }
  }
  if(optind == argc) {
    std::string pw1, pw2;

    for(;;) {
      pw1 = getpass("Enter password: ");
      pw2 = getpass("Reytpe password: ");
      if(pw1 == pw2)
        break;
      fprintf(stderr, "ERROR: password do not match\n");
    }
    printf("%s\n", encrypt(pw1).c_str());
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
