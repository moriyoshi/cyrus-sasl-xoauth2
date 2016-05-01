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
  AS_HELP_STRING([--with-cyrus-sasl=[[PREFIX]]], [Installation prefix of Cyrus-SASL]),
  [CYRUS_SASL_PREFIX=$withval],
  [CYRUS_SASL_PREFIX=]
)

for prefix in "$CYRUS_SASL_PREFIX"; do
  ac_save_CPPFLAGS="$CPPFLAGS"
  CPPFLAGS="-I$prefix/include $CPPFLAGS"
  AC_CHECK_HEADER([sasl/saslplug.h], [
    CYRUS_SASL_CPPFLAGS="-I$prefix/include"
    CYRUS_SASL_PREFIX="$prefix"
  ])
  CPPFLAGS="$ac_save_CPPFLAGS"
  if test -n "$CYRUS_SASL_CPPFLAGS"; then
    break
  fi
done

if test -z "$CYRUS_SASL_PREFIX"; then
  AC_MSG_ERROR([Cyrus-SASL not found under $CYRUS_SASL_PREFIX])
fi

AC_SUBST([CYRUS_SASL_CPPFLAGS], [$CYRUS_SASL_CPPFLAGS])
AC_SUBST([CYRUS_SASL_PREFIX], [$CYRUS_SASL_PREFIX])
AC_OUTPUT
