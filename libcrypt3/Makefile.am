#
# This file is part of crypt3.
# Copyright © Richard Kettlewell
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the author nor the names of other contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
lib_LTLIBRARIES=libcrypt3.la
include_HEADERS=libcrypt3.h
libcrypt3_la_SOURCES=crypt.c libcrypt3.h crypt-des.c crypt-md5.c crypt-sha256.c crypt-sha512.c salt.c misc.c internal3.h
# See https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
# for rules about updating -version-info.
libcrypt3_la_LDFLAGS=-export-symbols ${srcdir}/libcrypt3.sym -version-info 0:0:0
EXTRA_DIST=mainpage.h usage.svg
