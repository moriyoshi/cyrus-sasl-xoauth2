ACLOCAL_AMFLAGS = -I m4
CYRYS_SASL_PREFIX = @CYRUS_SASL_PREFIX@
CYRYS_SASL_CPPFLAGS = @CYRUS_SASL_CPPFLAGS@
CYRUS_SASL_LDFLAGS = @CYRUS_SASL_LDFLAGS@

pkglibdir = ${CYRUS_SASL_PREFIX}/lib/sasl2
pkglib_LTLIBRARIES = libxoauth2.la
libxoauth2_la_CPPFLAGS = ${CYRUS_SASL_CPPFLAGS}
libxoauth2_la_LDFLAGS = ${CYRUS_SASL_LDFLAGS} -module
libxoauth2_la_SOURCES = xoauth2_str.c xoauth2_init.c xoauth2_server.c xoauth2_client.c
