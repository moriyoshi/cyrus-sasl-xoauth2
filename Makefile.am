SUBDIRS = . tests
ACLOCAL_AMFLAGS = -I m4
CYRYS_SASL_PREFIX = @CYRUS_SASL_PREFIX@
CYRYS_SASL_CPPFLAGS = @CYRUS_SASL_CPPFLAGS@
CYRUS_SASL_LDFLAGS = @CYRUS_SASL_LDFLAGS@
XOAUTH2_TOKEN_CONV_EXTRA_LIBS = @XOAUTH2_TOKEN_CONV_EXTRA_LIBS@

noinst_LTLIBRARIES = libxoauth2_token_conv.la
libxoauth2_token_conv_la_SOURCES = xoauth2_socket_common.c xoauth2_token_conv.c
if XOAUTH2_WIN32
libxoauth2_token_conv_la_SOURCES += xoauth2_socket_win32.c
else
libxoauth2_token_conv_la_SOURCES += xoauth2_socket_unix.c
endif

pkglibdir = ${CYRUS_SASL_PREFIX}/lib/sasl2
pkglib_LTLIBRARIES = libxoauth2.la
libxoauth2_la_CPPFLAGS = ${CYRUS_SASL_CPPFLAGS}
libxoauth2_la_LDFLAGS = ${CYRUS_SASL_LDFLAGS} -module
libxoauth2_la_SOURCES = xoauth2_str.c xoauth2_init.c xoauth2_server.c xoauth2_client.c
libxoauth2_la_LIBADD = libxoauth2_token_conv.la ${XOAUTH2_TOKEN_CONV_EXTRA_LIBS}
