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
#include <config.h>
#include <string>

#include "libcrypt3.h"

struct test_case {
  const std::string salt;
  const std::string password;
  const std::string result;
};

const struct test_case test_cases[] = {
  // Test cases from Glicb DES implementation
  { "ea", "", "eaIv9eteVyQUM" },
  { "dU", "test", "dUVg5tMcYpY1I" },
  { "dU", "\xF4\xE5\xF3\xF4", "dUVg5tMcYpY1I" }, // bit 7 smashed
  { "qS", "12345678", "qS/dKOl1JA5vE" },
  { "qS", "123456789abcdef0", "qS/dKOl1JA5vE" }, // truncated to first 8
  // Test cases from Glibc MD5 implementation
  { "$1$2LdT.pCZ$", "", "$1$2LdT.pCZ$7ypw5lrdCefp89Ob7hbrC0" },
  { "$1$Oh3l/BKE$", "test", "$1$Oh3l/BKE$WT19fwozEheRq4KUSwjMn1" },
  { "$1$Oh3l/BKE$", "\xF4\xE5\xF3\xF4", "$1$Oh3l/BKE$lQh4go2azVbSkzPw5yVCq/" },
  { "$1$Oh3l/BKE", "test", "$1$Oh3l/BKE$WT19fwozEheRq4KUSwjMn1" },
  { "$1$pEKu..Rz$", "12345678", "$1$pEKu..Rz$VPrr6RH4qnBk4ovMK640.1" },
  { "$1$pEKu..Rz$", "123456789abcdef0", "$1$pEKu..Rz$Oi7/zZ4yOpGzJZXPjY.gw1" },
  // Test case from FreeBSD MD5 implementation
  { "$1$deadbeef$0Huu6KHrKLVWfqa4WljDE0", "0.s0.l33t",
    "$1$deadbeef$0Huu6KHrKLVWfqa4WljDE0" },
  // Test cases from Glibc SHA256 implementation
  { "$5$xBevT1DS8KW44fXc$", "",
    "$5$xBevT1DS8KW44fXc$s./rspOsOR8SxKI24j/VE3AVoqTJxV10b86UTXWlER1" },
  { "$5$771CLAf5q1y1dNL2$", "test",
    "$5$771CLAf5q1y1dNL2$zT1tZ6O81gL0X9W/Vva1vYfzhkqTbNn0jo3TK33T9O1" },
  { "$5$771CLAf5q1y1dNL2$", "\xF4\xE5\xF3\xF4",
    "$5$771CLAf5q1y1dNL2$7fsseqFSeMWiOBmxNpex883IeL5DoOuNyrtRpFkFQH4" },
  { "$5$771CLAf5q1y1dNL2", "test",
    "$5$771CLAf5q1y1dNL2$zT1tZ6O81gL0X9W/Vva1vYfzhkqTbNn0jo3TK33T9O1" },
  { "$5$LW4LThfdqh6Bz7sv$", "12345678",
    "$5$LW4LThfdqh6Bz7sv$cKPc6e9o61RIlB6noon1D0wT60MvxxkQa.En2xOrQh3" },
  { "$5$LW4LThfdqh6Bz7sv$", "123456789abcdef0",
    "$5$LW4LThfdqh6Bz7sv$9XRqxNtIGURvQqXt/Qh5.8qd9TP0f6d9QQsSe/8Wwp0" },
  // Test cases from Glibc SHA512 implementation
  { "$6$wTonSTftbAlySRbm$", "",
    "$6$wTonSTftbAlySRbm$Pj5iduiCImNBnFspPlxMhv."
    "TSLbkScfJWuCTYQE3G67xnvVzMl1EABZ76F3CpyG5Yc/QKd3BF7JS60hYctcRw/" },
  { "$6$hw0T71PRetoVoDWi$", "test",
    "$6$hw0T71PRetoVoDWi$P/dem7ew9EYvvLm5GJlH0dfP56Fwb0I6sknFD6kyAX/"
    "IwN0gPYVwhikMfn6yoUgAlnXYCESC4uhMWtsXMLm3A." },
  { "$6$hw0T71PRetoVoDWi$", "\xF4\xE5\xF3\xF4",
    "$6$hw0T71PRetoVoDWi$pKU3NYBMgCFf."
    "FjSiAe4lFnUduHDPGxg74KZxZhrBKYWr0o3AqoUPtNsKgXXhBHSI7IN145Sn6ARxuUVSNK/"
    "3." },
  { "$6$hw0T71PRetoVoDWi$", "test",
    "$6$hw0T71PRetoVoDWi$P/dem7ew9EYvvLm5GJlH0dfP56Fwb0I6sknFD6kyAX/"
    "IwN0gPYVwhikMfn6yoUgAlnXYCESC4uhMWtsXMLm3A." },
  { "$6$hUxeZIDLWCspRxjK$", "12345678",
    "$6$hUxeZIDLWCspRxjK$fmhvxiXo2Ch.UkAmNmk9TVrbnPXT."
    "WhBj2RxpjOTHRqI1xSGqesUzla5z1IM531abQx5f8LpF1lmcgY8MkMmC/" },
  { "$6$hUxeZIDLWCspRxjK$", "123456789abcdef0",
    "$6$hUxeZIDLWCspRxjK$"
    "J6tAIKmWvLax9vAugJMobLe1OPmTcyK6h1RFJHzlhIRhDkGnC3RHi3ph0CAyoXGPD55HyfKKiG"
    "kFKIv.fmSy51" },
};

int main() {
  int errors = 0;
  std::string encrypted;
  for(const auto &tc : test_cases) {
    encrypted = libcrypt3_crypt(tc.password.c_str(), tc.salt.c_str());
    if(encrypted != tc.result) {
      fprintf(stderr,
              "ERROR: salt=%s password=%s\n"
              "expected=%s\n"
              "     got=%s\n",
              tc.salt.c_str(), tc.password.c_str(), tc.result.c_str(),
              encrypted.c_str());
      ++errors;
    }
  }
  return !!errors;
}
