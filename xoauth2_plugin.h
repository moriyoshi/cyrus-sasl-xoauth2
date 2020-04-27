/*
 * Copyright (c) 2016 Moriyoshi Koizumi
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
#ifndef XOAUTH2_PLUGIN_H
#define XOAUTH2_PLUGIN_H

#include <sasl/sasl.h>
#include <sasl/saslplug.h>

#define UNUSED(x) x __attribute__((unused))

typedef struct {
    unsigned size;
    unsigned len;
    char *buf;
} xoauth2_plugin_str_t;

typedef struct {
    char *buf;
    unsigned buf_size;
    char *authid;
    unsigned authid_len;
    char *token_type;
    unsigned token_type_len;
    char *token;
    unsigned token_len;
} xoauth2_plugin_auth_response_t;

typedef struct {
    const char *scope;
    unsigned scope_len;
} xoauth2_plugin_server_settings_t;

typedef struct {
    xoauth2_plugin_server_settings_t *settings;
    int state;
    xoauth2_plugin_auth_response_t resp;
    xoauth2_plugin_str_t outbuf;
} xoauth2_plugin_server_context_t;

typedef struct _xoauth2_plugin_client_global_context_t xoauth2_plugin_client_global_context_t;

typedef struct {
    xoauth2_plugin_client_global_context_t *glob_context;
    int state;
    xoauth2_plugin_auth_response_t resp;
    xoauth2_plugin_str_t outbuf;
    xoauth2_plugin_str_t token;
} xoauth2_plugin_client_context_t;

int xoauth2_plugin_str_init(const sasl_utils_t *utils, xoauth2_plugin_str_t *s);
int xoauth2_plugin_str_alloc(const sasl_utils_t *utils, xoauth2_plugin_str_t *s, unsigned req_len);
int xoauth2_plugin_str_append(const sasl_utils_t *utils, xoauth2_plugin_str_t *s, const char *v, unsigned vlen);
void xoauth2_plugin_str_free(const sasl_utils_t *utils, xoauth2_plugin_str_t *s);

int xoauth2_server_plug_init(
        const sasl_utils_t *utils,
        int maxversion,
        int *out_version,
        sasl_server_plug_t **pluglist,
        int *plugcount);

int xoauth2_client_plug_init(
        const sasl_utils_t *utils,
        int maxversion,
        int *out_version,
        sasl_client_plug_t **pluglist,
        int *plugcount);

#define SASL_log(args) (utils->log args)
#define SASL_seterror(args) (utils->seterror args)
#define SASL_malloc(size) (utils->malloc(size))
#define SASL_free(p) (utils->free(p))
#define SASL_base64_encode(in, in_len, out, out_max_len, out_len) (utils->encode64(in, in_len, out, out_max_len, out_len))
#define SASL_base64_decode(in, in_len, out, out_max_len, out_len) (utils->decode64(in, in_len, out, out_max_len, out_len))

#define SASL_AUX_OAUTH2_BEARER_TOKENS "oauth2BearerTokens"

#ifdef WIN32
#define SASLPLUGINAPI __declspec(dllexport)
#else
#define SASLPLUGINAPI extern
#endif

#endif /* XOAUTH2_PLUGIN_H */
