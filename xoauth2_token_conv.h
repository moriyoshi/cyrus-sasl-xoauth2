/*
 * Copyright (c) 2020 Moriyoshi Koizumi
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#ifndef XOAUTH2_TOKEN_CONV_H
#define XOAUTH2_TOKEN_CONV_H

#include "xoauth2_plugin.h"

typedef struct {
    int connect_timeout;
    int write_timeout;
    int read_timeout;
} xoauth2_plugin_token_conv_settings_t;

typedef struct _xoauth2_plugin_socket_t xoauth2_plugin_socket_t;

typedef struct {
    const xoauth2_plugin_token_conv_settings_t *settings;
    xoauth2_plugin_str_t family;
    xoauth2_plugin_str_t addr;
    xoauth2_plugin_socket_t *s;
} xoauth2_plugin_token_conv_t;

typedef struct _xoauth2_plugin_socket_iovec_t xoauth2_plugin_socket_iovec_t;

int xoauth2_plugin_token_conv_init(const sasl_utils_t *utils, xoauth2_plugin_token_conv_t *token_conv, const xoauth2_plugin_token_conv_settings_t *settings, const char *family_and_addr);
void xoauth2_plugin_token_conv_free(const sasl_utils_t *utils, xoauth2_plugin_token_conv_t *token_conv);
int xoauth2_plugin_token_conv_retrieve_access_token(const sasl_utils_t *utils, xoauth2_plugin_token_conv_t *token_conv, xoauth2_plugin_str_t *retval, const char *authid, unsigned authid_len);

#endif /* XOAUTH2_TOKEN_CONV_H */
