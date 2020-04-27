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

#ifdef __CYGWIN__
#undef WIN32
#undef _WIN32
#endif

#ifdef HAVE_POLL_H
#include <poll.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <string.h>
#include <errno.h>
#include <stdio.h>

#include "xoauth2_token_conv.h"
#include "xoauth2_socket.h"

typedef struct {
    int af; /* address family */
    union {
        struct addrinfo *addr;
        struct sockaddr_un sun;
    } addr;
} xoauth2_plugin_unix_addr_info_t;

typedef struct _xoauth2_plugin_unix_socket_t {
    const xoauth2_plugin_socket_vtbl_t *vtbl;
    int s;
} xoauth2_plugin_unix_socket_t;

static int addrinfo_error_to_sasl_code(int eai)
{
    switch (eai) {
    case 0:
        return SASL_OK;
    case EAI_AGAIN:
        return SASL_TRYAGAIN;
    case EAI_MEMORY:
        return SASL_NOMEM;
    }
    return SASL_FAIL;
}

static int xoauth2_plugin_unix_addr_info_lookup(const sasl_utils_t *utils, xoauth2_plugin_unix_addr_info_t *info, int af, const xoauth2_plugin_host_port_pair_t *host_port_pair)
{
    info->af = af;

    if (info->af == AF_UNIX) {
        size_t n = strlen(host_port_pair->host);
        if (sizeof(info->addr.sun.sun_path) < n + 1) {
            return SASL_BADPARAM;
        }
        info->addr.sun.sun_family = AF_UNIX;
        memcpy(info->addr.sun.sun_path, host_port_pair->host, n + 1);
        return SASL_OK;
    }

    {
        struct addrinfo hint;
        struct addrinfo *results;
        int ais;

        hint.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG;
        hint.ai_family = af;
        hint.ai_socktype = SOCK_STREAM;
        hint.ai_protocol = IPPROTO_TCP;
        hint.ai_addrlen = 0;
        hint.ai_addr = NULL;
        hint.ai_canonname = NULL;
        hint.ai_next = NULL;

        SASL_log((utils->conn, SASL_LOG_DEBUG, "xoauth2: lookup %s:%s with getaddrinfo()", host_port_pair->host, host_port_pair->port_or_service));
        ais = getaddrinfo(
            host_port_pair->host,
            host_port_pair->port_or_service,
            &hint,
            &results);
        if (ais) {
            SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: getaddrinfo() returned error %d (%s)", ais, gai_strerror(ais)));
        }
        info->addr.addr = results;
        return addrinfo_error_to_sasl_code(ais);
    }
}

static void xoauth2_plugin_unix_addr_info_free(const sasl_utils_t *utils, xoauth2_plugin_unix_addr_info_t *info)
{
    if (info->af != AF_UNIX) {
        freeaddrinfo(info->addr.addr);
    }
}

static int xoauth2_plugin_unix_socket_read(const sasl_utils_t *utils, xoauth2_plugin_unix_socket_t *s, xoauth2_plugin_socket_iovec_t *iv, size_t nivs, unsigned *nread, unsigned minread, int timeout_ms)
{
    unsigned total_sz;
    const xoauth2_plugin_socket_iovec_t *e;

    /* Roll to INT_MAX */
    if (nivs > (((uint32_t)-1) >> 1)) {
        nivs = (((uint32_t)-1) >> 1);
    }

    e = iv + nivs;
    {
        const xoauth2_plugin_socket_iovec_t *p;
        total_sz = 0;
        for (p = iv, e = iv + nivs; p < e; p++) {
            if (total_sz + p->iov_len < total_sz) {
                total_sz = (((uint32_t)-1) >> 1);
                break;
            }
            if (total_sz > (((uint32_t)-1) >> 1)) {
                total_sz = (((uint32_t)-1) >> 1);
                break;
            }
            total_sz += p->iov_len;
        }
    }

    if (!minread) {
        minread = total_sz;
    }

    *nread = 0;
    {
        struct pollfd fds[] = { s->s, POLLIN | POLLHUP, 0 };
        char buf[1024] = "(unknown error)";
        int first = 1;
        while (*nread < minread) {
            int n;
            /* optimization; no polling on the first try */
            if (!first) {
                int pn = poll(fds, sizeof(fds) / sizeof(*fds), timeout_ms < 0 ? -1 : timeout_ms);
                switch (pn) {
                case -1:
                    strerror_r(errno, buf, sizeof(buf));
                    SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: poll() returned error %d (%s)", errno, buf));
                    return SASL_FAIL;
                case 0:
                    SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: timed out"));
                    return SASL_FAIL;
                }
            }
            n = readv(s->s, (struct iovec *)iv, nivs);
            first = 0;
            if (-1 == n) {
                if (EWOULDBLOCK == errno) {
                    continue;
                }
                strerror_r(errno, buf, sizeof(buf));
                SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: readv() returned error %d (%s)", errno, buf));
                return SASL_FAIL;
            }
            if (n == 0) {
                /* EOF */
                break;
            }
            *nread += n;
            if (iv >= e) {
                SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: unexpected condition"));
                return SASL_FAIL;
            }
            while (n > iv->iov_len) {
                n -= iv->iov_len;
                ++iv;
                --nivs;
            }
            *((unsigned char **)&iv->iov_base) += n;
            iv->iov_len -= n;
        }
        return SASL_OK;
    }
}

static int xoauth2_plugin_unix_socket_write(const sasl_utils_t *utils, xoauth2_plugin_unix_socket_t *s, xoauth2_plugin_socket_iovec_t *iv, size_t nivs, unsigned *nwritten, int timeout_ms)
{
    size_t total_sz;
    const xoauth2_plugin_socket_iovec_t *e;

    /* Roll to INT_MAX */
    if (nivs > (((uint32_t)-1) >> 1)) {
        nivs = (((uint32_t)-1) >> 1);
    }

    e = iv + nivs;
    {
        const xoauth2_plugin_socket_iovec_t *p;
        total_sz = 0;
        for (p = iv, e = iv + nivs; p < e; p++) {
            if (total_sz + p->iov_len < total_sz) {
                total_sz = (((uint32_t)-1) >> 1);
                break;
            }
            if (total_sz > (((uint32_t)-1) >> 1)) {
                total_sz = (((uint32_t)-1) >> 1);
                break;
            }
            total_sz += p->iov_len;
        }
    }

    *nwritten = 0;
    {
        struct pollfd fds[] = { s->s, POLLOUT | POLLHUP, 0 };
        char buf[1024] = "(unknown error)";
        while (*nwritten < total_sz) {
            int n;
            {
                int pn = poll(fds, sizeof(fds) / sizeof(*fds), timeout_ms < 0 ? -1 : timeout_ms);
                switch (pn) {
                case -1:
                    strerror_r(errno, buf, sizeof(buf));
                    SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: poll() returned error %d (%s)", errno, buf));
                    return SASL_FAIL;
                case 0:
                    SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: timed out"));
                    return SASL_FAIL;
                }
            }
            n = writev(s->s, (struct iovec *)iv, nivs);
            if (-1 == n) {
                if (EWOULDBLOCK == errno) {
                    continue;
                }
                strerror_r(errno, buf, sizeof(buf));
                SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: writev() returned error %d (%s)", errno, buf));
                return SASL_FAIL;
            }
            *nwritten += n;
            if (iv >= e) {
                SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: unexpected condition"));
                return SASL_FAIL;
            }
            while (n > iv->iov_len) {
                n -= iv->iov_len;
                ++iv;
                --nivs;
            }
            *((unsigned char **)&iv->iov_base) += n;
            iv->iov_len -= n;
        }
        return SASL_OK;
    }
}

void xoauth2_plugin_unix_socket_close(UNUSED(const sasl_utils_t *utils), xoauth2_plugin_unix_socket_t *s)
{
    if (-1 == s->s) {
        return;
    }
    SASL_log((utils->conn, SASL_LOG_NOTE, "xoauth2: socket closed"));
    close(s->s);
    s->s = -1;
}

static void xoauth2_plugin_unix_socket_cleanup(const sasl_utils_t *utils, xoauth2_plugin_unix_socket_t *s)
{
    xoauth2_plugin_unix_socket_close(utils, s);
    SASL_free(s);
}

static const xoauth2_plugin_socket_vtbl_t xoauth2_plugin_unix_socket_vtbl = {
    (xoauth2_plugin_socket_cleanup_fn_t)xoauth2_plugin_unix_socket_cleanup,
    (xoauth2_plugin_socket_close_fn_t)xoauth2_plugin_unix_socket_close,
    (xoauth2_plugin_socket_read_fn_t)xoauth2_plugin_unix_socket_read,
    (xoauth2_plugin_socket_write_fn_t)xoauth2_plugin_unix_socket_write
};

static int xoauth2_plugin_unix_socket_conv_af(enum xoauth2_plugin_af af)
{
    switch (af) {
    case XOAUTH2_PLUGIN_UNIX_AF_UNSPEC:
        return AF_UNSPEC;
    case XOAUTH2_PLUGIN_UNIX_AF_UNIX:
        return AF_UNIX;
    case XOAUTH2_PLUGIN_UNIX_AF_INET:
        return AF_INET;
    case XOAUTH2_PLUGIN_UNIX_AF_INET6:
        return AF_INET6;
    default:
        return AF_UNSPEC;
    }
}

int xoauth2_plugin_unix_socket_connect(const sasl_utils_t *utils, xoauth2_plugin_socket_t **retval, enum xoauth2_plugin_af _af, const char *addr, int timeout_ms)
{
    int err;
    int af = xoauth2_plugin_unix_socket_conv_af(_af);
    xoauth2_plugin_unix_addr_info_t info = { -1 };
    xoauth2_plugin_host_port_pair_t *pair = NULL;
    xoauth2_plugin_unix_socket_t *s;

    s = SASL_malloc(sizeof(xoauth2_plugin_unix_socket_t));
    if (!s) {
        return SASL_NOMEM;
    }
    s->vtbl = &xoauth2_plugin_unix_socket_vtbl;
    s->s = -1;

    if (af == AF_UNIX) {
        err = xoauth2_plugin_host_port_pair_new_no_port(utils, &pair, addr);
    } else {
        err = xoauth2_plugin_host_port_pair_new(utils, &pair, addr, "65321");
    }
    if (SASL_OK != err) {
        goto out;
    }
    err = xoauth2_plugin_unix_addr_info_lookup(utils, &info, af, pair);
    if (SASL_OK != err) {
        goto out;
    }

    {
        struct addrinfo tmp;
        struct addrinfo *addr;

        if (AF_UNIX == info.af) {
            tmp.ai_family = info.af;
            tmp.ai_protocol = 0;
            tmp.ai_addr = (struct sockaddr *)&info.addr.sun;
            tmp.ai_addrlen = sizeof(info.addr.sun);
            tmp.ai_next = NULL;
            addr = &tmp;
        } else {
            addr = info.addr.addr;
        }
        for (; addr; addr = addr->ai_next) {
            char buf[1024] = "(unknown error)";
            int _errno;
            static const int nonzero = 1;
            s->s = socket(addr->ai_family, SOCK_STREAM, addr->ai_protocol);
            if (-1 == s->s) {
                strerror_r(errno, buf, sizeof(buf));
                SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: socket() returned error %d (%s)", errno, buf));
                err = SASL_FAIL;
                goto out;
            }
            if (0 != ioctl(s->s, FIONBIO, &nonzero)) {
                strerror_r(errno, buf, sizeof(buf));
                SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: ioctl() returned error %d (%s)", errno, buf));
                err = SASL_FAIL;
                goto out;
            }
            if (connect(s->s, addr->ai_addr, addr->ai_addrlen)) {
                _errno = errno;
                if (_errno != EINPROGRESS) {
                    close(s->s);
                    strerror_r(_errno, buf, sizeof(buf));
                    SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: connect() returned error %d (%s)", _errno, buf));
                    err = SASL_FAIL;
                    continue;
                }
            }
            {
                struct pollfd fds[] = { s->s, POLLIN | POLLOUT | POLLHUP, 0 };
                int n;
                n = poll(fds, sizeof(fds) / sizeof(*fds), timeout_ms < 0 ? -1 : timeout_ms);
                switch (n) {
                case -1:
                    _errno = errno;
                    close(s->s);
                    strerror_r(_errno, buf, sizeof(buf));
                    SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: poll() returned error %d (%s)", _errno, buf));
                    err = SASL_FAIL;
                    goto out;
                case 0:
                    SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: poll() timed out"));
                    err = SASL_FAIL;
                    continue;
                }
                if (fds[0].revents & (POLLHUP | POLLERR)) {
                    int _errno;
                    socklen_t _errno_len = sizeof(_errno);
                    if (-1 == getsockopt(s->s, SOL_SOCKET, SO_ERROR, &_errno, &_errno_len)) {
                        _errno = errno;
                        close(s->s);
                        strerror_r(_errno, buf, sizeof(buf));
                        SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: getsockopt() returned error %d (%s)", _errno, buf));
                        err = SASL_FAIL;
                        goto out;
                    }
                    if (_errno == ECONNREFUSED) {
                        SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: connection refused"));
                        err = SASL_FAIL;
                        continue;
                    }
                    close(s->s);
                    strerror_r(_errno, buf, sizeof(buf));
                    SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: connect failed: %d (%s)", _errno, buf));
                    err = SASL_FAIL;
                    goto out;
                }
            }
            break;
        }
        if (!addr) {
            err = SASL_FAIL;
            goto out;
        }
    }
    *retval = (xoauth2_plugin_socket_t *)s;
out:
    if (pair) {
        xoauth2_plugin_host_port_pair_free(utils, pair);
    }
    if (info.af >= 0) {
        xoauth2_plugin_unix_addr_info_free(utils, &info);
    }
    if (SASL_OK != err) {
        xoauth2_plugin_unix_socket_cleanup(utils, s);
    }
    return err;
}

int xoauth2_plugin_unix_socket_setup()
{
    return SASL_OK;
}

void xoauth2_plugin_unix_socket_teardown()
{
}
