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
AC_PREREQ([2.61])
AC_INIT([crypt3], [0], [rjk@greenend.org.uk])
AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_AUX_DIR([config.aux])
AM_INIT_AUTOMAKE([foreign])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CONFIG_SRCDIR([crypt3.c])
AM_CONFIG_HEADER([config.h])
AC_LANG([C++])
AC_PROG_CC
AC_CHECK_LIB([crypt],[crypt],[LIBCRYPT=-lcrypt])
AC_SUBST([LIBCRYPT])
AC_PROG_LIBTOOL
case $(uname -n) in
Darwin )
  ;;
* )
  AC_CHECK_LIB([crypto],[SHA256_Init])
  ;;
esac
AC_SET_MAKE
AC_DEFINE([_GNU_SOURCE], [1], [use GNU extensions])
if test "x$GCC" = xyes; then
  CFLAGS="$CFLAGS -Wall -W -Werror -Wpointer-arith -Wwrite-strings"
fi
AH_BOTTOM([#ifdef __GNUC__
# define attribute(x) __attribute__(x)
#else
# define attribute(x)
#endif])
AC_CONFIG_FILES([Makefile libcrypt3/Makefile])
AC_OUTPUT
