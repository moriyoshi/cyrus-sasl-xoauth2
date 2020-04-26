#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <locale.h>

#include "xoauth2_token_conv.h"
#include "xoauth2_socket.h"

static void _log(UNUSED(sasl_conn_t *conn), int level, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fputs("\n", stderr);
    va_end(ap);
}

static const xoauth2_plugin_token_conv_settings_t settings = { 2000, 2000, 2000 };

static int do_converse(const sasl_utils_t *utils, const char *addr)
{
    int err;
    xoauth2_plugin_token_conv_t token_conv;
    xoauth2_plugin_str_t str;

    err = xoauth2_plugin_str_init(utils, &str);
    if (SASL_OK != err) {
        xoauth2_plugin_token_conv_free(utils, &token_conv);
        return err;
    }

    {
        int i;
        for (i = 0; i < 3; i++) {
            int j;
            err = xoauth2_plugin_token_conv_init(utils, &token_conv, &settings, addr);
            if (SASL_OK != err) {
                xoauth2_plugin_str_free(utils, &str);
                return err;
            }
            for (j = 0; j < 3; j++) {
                str.len = 0;
                err = xoauth2_plugin_token_conv_retrieve_access_token(utils, &token_conv, &str, "AUTHID!", sizeof("AUTHID!") - 1);
                if (SASL_OK != err) {
                    xoauth2_plugin_str_free(utils, &str);
                    xoauth2_plugin_token_conv_free(utils, &token_conv);
                    return err;
                }
                fprintf(stderr, "(%d) %s\n", str.len, str.buf);
            }
            xoauth2_plugin_token_conv_free(utils, &token_conv);
        }
    }

    xoauth2_plugin_str_free(utils, &str);

    return SASL_OK;
}

int main()
{
    sasl_utils_t utils;

    setlocale(LC_ALL, "");

    utils.log = _log;
    utils.malloc = malloc;
    utils.calloc = calloc;
    utils.realloc = realloc;
    utils.free = free;

    xoauth2_plugin_socket_setup();
    do_converse(&utils, "tcp:127.0.0.1:65321");
    do_converse(&utils, "unix:/tmp/test.sock");
    xoauth2_plugin_socket_teardown();
}
