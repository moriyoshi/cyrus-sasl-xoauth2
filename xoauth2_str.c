#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include "xoauth2_plugin.h"

const char empty_string[] = "";

int xoauth2_plugin_str_init(const sasl_utils_t *utils, xoauth2_plugin_str_t *s)
{
    s->size = 0;
    s->len = 0;
    s->buf = (char *)empty_string;
    return SASL_OK;
}

int xoauth2_plugin_str_alloc(const sasl_utils_t *utils, xoauth2_plugin_str_t *s, unsigned req_len)
{
    if (req_len >= s->size) {
        char *new_buf = s->buf == empty_string ? NULL: s->buf;
        unsigned new_size = s->size + 1;
        while (new_size < req_len) {
            unsigned _new_size = new_size + (new_size >> 1);
            if (_new_size < new_size) {
                return SASL_NOMEM;
            }
            new_size = _new_size;
        }
        new_buf = utils->realloc(new_buf, new_size);
        if (!new_buf) {
            return SASL_NOMEM;
        }
        s->buf = new_buf;
        s->size = new_size;
    }
    return SASL_OK;
}

int xoauth2_plugin_str_append(const sasl_utils_t *utils, xoauth2_plugin_str_t *s, const char *v, unsigned vlen)
{
    int err;
    unsigned req_len = s->len + vlen + 1;
    if (req_len < s->len) {
        return SASL_NOMEM;
    }
    err = xoauth2_plugin_str_alloc(utils, s, req_len);
    if (err != SASL_OK) {
        return err;
    }
    memcpy(s->buf + s->len, v, vlen);
    s->len += vlen;
    s->buf[s->len] = '\0';
    return SASL_OK;
}

void xoauth2_plugin_str_free(const sasl_utils_t *utils, xoauth2_plugin_str_t *s)
{
    if (s->buf && s->buf != empty_string) {
        SASL_free(s->buf);
        s->buf = (char *)empty_string;
        s->len = s->size = 0;
    }
}

