dnl Copyright (c) 2016 Moriyoshi Koizumi
dnl 
dnl Permission is hereby granted, free of charge, to any person obtaining a
dnl copy of this software and associated documentation files (the "Software"),
dnl to deal in the Software without restriction, including without limitation
dnl the rights to use, copy, modify, merge, publish, distribute, sublicense,
dnl and/or sell copies of the Software, and to permit persons to whom the
dnl Software is furnished to do so, subject to the following conditions:
dnl 
dnl The above copyright notice and this permission notice shall be included in
dnl all copies or substantial portions of the Software.
dnl 
dnl THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
dnl IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
dnl FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
dnl AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
dnl LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
dnl FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
dnl DEALINGS IN THE SOFTWARE.

AC_INIT([cyrus-sasl-xoauth2], [0.0])
AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
LT_INIT
AC_PROG_CC
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

CYRUS_SASL_CPPFLAGS=
CYRUS_SASL_PREFIX=/usr

AC_ARG_WITH(
  [cyrus-sasl],
  AS_HELP_STRING([--with-cyrus-sasl=[[PREFIX]]], [Installation prefix of Cyrus-SASL (defaults to /usr)]),
  [CYRUS_SASL_PREFIXES=$withval],
  [CYRUS_SASL_PREFIXES=/usr]
)

for prefix in "$CYRUS_SASL_PREFIXES"; do
  ac_save_CPPFLAGS="$CPPFLAGS"
  CPPFLAGS="-I$prefix/include $CPPFLAGS"
  AC_CHECK_HEADER([sasl/sasl.h], [
    CYRUS_SASL_CPPFLAGS="-I$prefix/include"
    CYRUS_SASL_PREFIX="$prefix"
  ])
  CPPFLAGS="$ac_save_CPPFLAGS"
  if test -n "$CYRUS_SASL_PREFIX"; then
    break
  fi
done

if test -z "$CYRUS_SASL_PREFIX"; then
  AC_MSG_ERROR([Cyrus-SASL not found under $CYRUS_SASL_PREFIX])
fi

AC_SUBST([CYRUS_SASL_CPPFLAGS], [$CYRUS_SASL_CPPFLAGS])
AC_SUBST([CYRUS_SASL_PREFIX], [$CYRUS_SASL_PREFIX])
AC_OUTPUT
