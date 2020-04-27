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
#ifndef XOAUTH2_SOCKET_H
#define XOAUTH2_SOCKET_H

#include <sasl/sasl.h>
#include <sasl/saslplug.h>

typedef struct {
    char *host;
    char *port_or_service;
} xoauth2_plugin_host_port_pair_t;

typedef struct _xoauth2_plugin_socket_t xoauth2_plugin_socket_t;

int xoauth2_plugin_host_port_pair_new(
        const sasl_utils_t *utils,
        xoauth2_plugin_host_port_pair_t **retval,
        const char *host_port_pair,
        const char *default_service);
int xoauth2_plugin_host_port_pair_new_no_port(
        const sasl_utils_t *utils,
        xoauth2_plugin_host_port_pair_t **retval,
        const char *host);
void xoauth2_plugin_host_port_pair_free(
        const sasl_utils_t *utils,
        xoauth2_plugin_host_port_pair_t *hp);

typedef struct _xoauth2_plugin_socket_iovec_t {
    void *iov_base;
    size_t iov_len;
} xoauth2_plugin_socket_iovec_t;

typedef void (*xoauth2_plugin_socket_cleanup_fn_t)(
        const sasl_utils_t *utils,
        xoauth2_plugin_socket_t *s);
typedef void (*xoauth2_plugin_socket_close_fn_t)(
        const sasl_utils_t *utils,
        xoauth2_plugin_socket_t *s);
typedef int (*xoauth2_plugin_socket_read_fn_t)(
        const sasl_utils_t *utils,
        xoauth2_plugin_socket_t *s,
        xoauth2_plugin_socket_iovec_t *iv,
        size_t nivs,
        unsigned *nread,
        unsigned minread,
        int timeout_ms);
typedef int (*xoauth2_plugin_socket_write_fn_t)(
        const sasl_utils_t *utils,
        xoauth2_plugin_socket_t *s,
        xoauth2_plugin_socket_iovec_t *iv,
        size_t nivs,
        unsigned *nwritten,
        int timeout_ms);

typedef struct {
    xoauth2_plugin_socket_cleanup_fn_t cleanup;
    xoauth2_plugin_socket_cleanup_fn_t close;
    xoauth2_plugin_socket_read_fn_t read;
    xoauth2_plugin_socket_write_fn_t write;
} xoauth2_plugin_socket_vtbl_t;

typedef struct _xoauth2_plugin_socket_t {
    xoauth2_plugin_socket_vtbl_t *vtbl;
} xoauth2_plugin_socket_t;


#define xoauth2_plugin_socket_cleanup(utils, s) \
        ((xoauth2_plugin_socket_t *)(s))->vtbl->cleanup((utils), (xoauth2_plugin_socket_t *)(s))
#define xoauth2_plugin_socket_close(utils, s) \
        ((xoauth2_plugin_socket_t *)(s))->vtbl->close((utils), (xoauth2_plugin_socket_t *)(s))
#define xoauth2_plugin_socket_read(utils, s, iv, nivs, nread, minread, timeout_ms) \
        ((xoauth2_plugin_socket_t *)(s))->vtbl->read((utils), (xoauth2_plugin_socket_t *)(s), (iv), (nivs), (nread), (minread), (timeout_ms))
#define xoauth2_plugin_socket_write(utils, s, iv, nivs, nwrite, timeout_ms) \
        ((xoauth2_plugin_socket_t *)(s))->vtbl->write((utils), (xoauth2_plugin_socket_t *)(s), (iv), (nivs), (nwrite), (timeout_ms))

enum xoauth2_plugin_af {
    XOAUTH2_PLUGIN_UNKNOWN_AF,
    XOAUTH2_PLUGIN_UNIX_AF_UNSPEC,
    XOAUTH2_PLUGIN_UNIX_AF_UNIX,
    XOAUTH2_PLUGIN_UNIX_AF_INET,
    XOAUTH2_PLUGIN_UNIX_AF_INET6,
    XOAUTH2_PLUGIN_WIN32_AF_UNSPEC,
    XOAUTH2_PLUGIN_WIN32_AF_UNIX,
    XOAUTH2_PLUGIN_WIN32_AF_INET,
    XOAUTH2_PLUGIN_WIN32_AF_INET6
};

int xoauth2_plugin_socket_connect(const sasl_utils_t *utils, xoauth2_plugin_socket_t **retval, const char *family, const char *addr, int timeout_ms);

int xoauth2_plugin_socket_setup();
void xoauth2_plugin_socket_teardown();

#endif /* XOAUTH2_SOCKET_H */
