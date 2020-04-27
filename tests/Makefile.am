CYRYS_SASL_PREFIX = @CYRUS_SASL_PREFIX@
CYRYS_SASL_CPPFLAGS = @CYRUS_SASL_CPPFLAGS@
CYRUS_SASL_LDFLAGS = @CYRUS_SASL_LDFLAGS@
XOAUTH2_TOKEN_CONV_EXTRA_LIBS = @XOAUTH2_TOKEN_CONV_EXTRA_LIBS@

noinst_PROGRAMS = test_xoauth2_token_conv
test_xoauth2_token_conv_SOURCES = test_xoauth2_token_conv.c test_xoauth2_token_conv.h ../xoauth2_str.c
test_xoauth2_token_conv_CPPFLAGS = ${CYRUS_SASL_CPPFLAGS}
test_xoauth2_token_conv_LDADD = ../libxoauth2_token_conv.la ${CYRUS_SASL_LDFLAGS} ${XOAUTH2_TOKEN_CONV_EXTRA_LIBS}
