#
# This file is part of crypt3.
# Copyright © Richard Kettlewell
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
tag:=$(shell git describe --tags --dirty --always)
SUBDIRS=libcrypt3

bin_PROGRAMS=crypt3
crypt3_SOURCES=crypt3.c

noinst_PROGRAMS=test_crypt
test_crypt_SOURCES=test_crypt.c
TESTS=test_crypt

AM_CFLAGS=-DTAG=\"${tag}\"
AM_CPPFLAGS=-I ${top_srcdir}/libcrypt3
LDADD=libcrypt3/libcrypt3.la
man_MANS=crypt3.1
EXTRA_DIST=${man_MANS} README.md .clang-format .gitignore Doxyfile \
    debian/compat debian/control debian/copyright debian/rules debian/changelog
ACLOCAL_AMFLAGS=-I m4
