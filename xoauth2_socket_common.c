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
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif

#include <string.h>

#include "xoauth2_plugin.h"
#include "xoauth2_socket.h"
#include "xoauth2_socket_win32.h"
#include "xoauth2_socket_unix.h"

int xoauth2_plugin_host_port_pair_new(const sasl_utils_t *utils, xoauth2_plugin_host_port_pair_t **retval, const char *host_port_pair, const char *default_service)
{
    xoauth2_plugin_host_port_pair_t *hp;
    size_t n = strlen(host_port_pair) + 1;
    const char *p = strchr(host_port_pair, ':');
    char *s;
    if (p) {
        hp = SASL_malloc(sizeof(xoauth2_plugin_host_port_pair_t) + n);
        if (!hp) {
            return SASL_NOMEM;
        }
        s = (char *)(hp + 1);
        memcpy(s, host_port_pair, n);
        s[p - host_port_pair] = '\0';
        hp->host = s;
        hp->port_or_service = s + (p - host_port_pair) + 1;
    } else {
        size_t nn = strlen(default_service) + 1;
        hp = SASL_malloc(sizeof(xoauth2_plugin_host_port_pair_t) + n + nn);
        if (!hp) {
            return SASL_NOMEM;
        }
        s = (char *)(hp + 1);
        memcpy(s, host_port_pair, n);
        s[n - 1] = '\0';
        memcpy(s + n, default_service, nn);
        hp->host = s;
        hp->port_or_service = s + n;
    }
    *retval = hp;
    return SASL_OK;
}

int xoauth2_plugin_host_port_pair_new_no_port(const sasl_utils_t *utils, xoauth2_plugin_host_port_pair_t **retval, const char *host)
{
    xoauth2_plugin_host_port_pair_t *hp;
    size_t n = strlen(host) + 1;
    char *s;
    hp = SASL_malloc(sizeof(xoauth2_plugin_host_port_pair_t) + n);
    if (!hp) {
        return SASL_NOMEM;
    }
    s = (char *)(hp + 1);
    memcpy(s, host, n);
    s[n - 1] = '\0';
    hp->host = s;
    hp->port_or_service = NULL;
    *retval = hp;
    return SASL_OK;
}

void xoauth2_plugin_host_port_pair_free(const sasl_utils_t *utils, xoauth2_plugin_host_port_pair_t *hp)
{
    SASL_free(hp);
}

static enum xoauth2_plugin_af xoauth2_family_str_to_i(const char *family)
{
    if (strcasecmp(family, "unix") == 0) {
#if defined(XOAUTH2_WIN32) && !defined(__CYGWIN__)
        return XOAUTH2_PLUGIN_XOAUTH2_WIN32_AF_UNIX;
#else
        return XOAUTH2_PLUGIN_UNIX_AF_UNIX;
#endif
    } else if (strcasecmp(family, "tcp") == 0) {
#if defined(XOAUTH2_WIN32) && !defined(__CYGWIN__)
        return XOAUTH2_PLUGIN_XOAUTH2_WIN32_AF_UNSPEC;
#else
        return XOAUTH2_PLUGIN_UNIX_AF_UNSPEC;
#endif
    } else if (strcasecmp(family, "tcp4") == 0) {
#if defined(XOAUTH2_WIN32) && !defined(__CYGWIN__)
        return XOAUTH2_PLUGIN_XOAUTH2_WIN32_AF_INET;
#else
        return XOAUTH2_PLUGIN_UNIX_AF_INET;
#endif
    } else if (strcasecmp(family, "tcp6") == 0) {
#if defined(XOAUTH2_WIN32) && !defined(__CYGWIN__)
        return XOAUTH2_PLUGIN_XOAUTH2_WIN32_AF_INET6;
#else
        return XOAUTH2_PLUGIN_UNIX_AF_INET6;
#endif
    }
    return XOAUTH2_PLUGIN_UNKNOWN_AF;
}

int xoauth2_plugin_socket_connect(const sasl_utils_t *utils, xoauth2_plugin_socket_t **retval, const char *family, const char *addr, int timeout_ms)
{
    int err;
    enum xoauth2_plugin_af af = xoauth2_family_str_to_i(family);
    if (XOAUTH2_PLUGIN_UNKNOWN_AF == af) {
        SASL_log((utils->conn, SASL_LOG_NOTE, "xoauth2: unknown address family: %s", family));
        return SASL_FAIL;
    }
#ifdef XOAUTH2_WIN32
    err = xoauth2_plugin_win32_socket_connect(utils, retval, af, addr, timeout_ms);
#else
    err = xoauth2_plugin_unix_socket_connect(utils, retval, af, addr, timeout_ms);
#endif
    if (SASL_OK == err) {
        SASL_log((utils->conn, SASL_LOG_NOTE, "xoauth2: connected to %s:%s", family, addr));
    }
    return err;
}

int xoauth2_plugin_socket_setup()
{
    int err;
#ifdef XOAUTH2_WIN32
    err = xoauth2_plugin_win32_socket_setup();
    if (SASL_OK != err) {
        return err;
    }
#endif
    err = xoauth2_plugin_unix_socket_setup();
    if (SASL_OK != err) {
#ifdef XOAUTH2_WIN32
        xoauth2_plugin_win32_socket_teardown();
#endif
        return err;
    }
    return SASL_OK;
}

void xoauth2_plugin_socket_teardown()
{
#ifdef XOAUTH2_WIN32
    xoauth2_plugin_win32_socket_teardown();
#endif
    xoauth2_plugin_unix_socket_teardown();
}
