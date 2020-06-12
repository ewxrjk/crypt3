#include <config.h>
#include "libcrypt3.h"
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>

int libcrypt3_pick_salt(char buffer[], size_t bufsize, int alg, int rounds) {
  const char *prefix;
  size_t slen, sread = 0;
  char sbuffer[64];
  int randomfd = -1;
  int rc = -1;

  if(rounds < 0) {
    errno = EINVAL;
    goto error;
  }
  switch(alg) {
  case LIBCRYPT3_DES:
    prefix = "";
    slen = 2;
    if(rounds != 0 && rounds != 25) {
      errno = EINVAL;
      goto error;
    }
    break;
  case LIBCRYPT3_MD5:
    prefix = "$1$";
    slen = 8;
    if(rounds != 0 && rounds != 1000) {
      errno = EINVAL;
      goto error;
    }
    break;
  case LIBCRYPT3_SHA256:
    prefix = "$5$";
    slen = 16;
    break;
  case LIBCRYPT3_SHA512:
    prefix = "$6$";
    slen = 16;
    break;
  default: errno = EINVAL; goto error;
  }
  if(slen > sizeof sbuffer) {
    errno = EINVAL;
    goto error;
  }
  if((randomfd = open("/dev/urandom", O_RDONLY)) < 0) {
    goto error;
  }
  while(sread < slen) {
    ssize_t r = read(randomfd, sbuffer + sread, slen - sread);
    if(r < 0) {
      if(errno == EINTR)
        continue;
      goto error;
    }
    sread += r;
  }
  for(size_t i = 0; i < slen; i++)
    sbuffer[i] = LIBCRYPT3_ALPHABET[sbuffer[i] & 63];
  sbuffer[slen] = 0;
  if(rounds)
    rc = snprintf(buffer, bufsize, "%srounds=%d$%s", prefix, rounds, sbuffer);
  else
    rc = snprintf(buffer, bufsize, "%s%s", prefix, sbuffer);
  if(rc > (int)bufsize) {
    errno = ENAMETOOLONG;
    rc = -1;
    goto error;
  }
error:
  if(randomfd >= 0)
    close(randomfd);
  return rc;
}
