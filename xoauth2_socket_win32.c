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

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif

#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif

#ifdef HAVE_WS2DEF_H
#include <ws2def.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <windows.h>

#include <wchar.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#include "xoauth2_token_conv.h"
#include "xoauth2_socket.h"

typedef struct {
    int af; /* address family */
    union {
#ifdef WIN32_UDS
        struct sockaddr_un sun;
#endif
        PADDRINFOEXA addr;
    } addr;
} xoauth2_plugin_win32_addr_info_t;

typedef struct {
    const xoauth2_plugin_socket_vtbl_t *vtbl;
    SOCKET s;
} xoauth2_plugin_win32_socket_t;

static int ws2_strerror(int _errno, char *buf, size_t buf_size)
{
    DWORD n;
    WCHAR _buf[4096];
    n = FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM,
        NULL,
        (DWORD)_errno,
        0,
        _buf,
        (DWORD)sizeof(_buf),
        NULL
    );
    if (0 == n) {
        return 1;
    }
    {
        mbstate_t mbs;
        const WCHAR *p = _buf;
        memset(&mbs, 0, sizeof(mbs));
        wcsrtombs(buf, &p, buf_size, &mbs);
    }
    {
        char *p = buf + strlen(buf);
        while (--p > buf && (*p == '\n' || *p == '\r'));
        *(p + 1) = '\0';
    }
    return 0;
}

static int addrinfo_error_to_sasl_code(int ws2s)
{
    switch (ws2s) {
    case 0:
        return SASL_OK;
    case EAI_AGAIN:
        return SASL_TRYAGAIN;
    case EAI_MEMORY:
        return SASL_NOMEM;
    }
    return SASL_FAIL;
}

static int xoauth2_plugin_win32_addr_info_lookup(const sasl_utils_t *utils, xoauth2_plugin_win32_addr_info_t *info, int af, const xoauth2_plugin_host_port_pair_t *host_port_pair)
{
    info->af = af;

#ifdef WIN32_UDS
    if (AF_UNIX == info->af) {
        size_t n = strlen(host_port_pair->host);
        if (sizeof(info->addr.sun.sun_path) < n + 1) {
            return SASL_BADPARAM;
        }
        info->addr.sun.sun_family = AF_UNIX;
        memcpy(info->addr.sun.sun_path, host_port_pair->host, n + 1);
        return SASL_OK;
    }
#endif

    {
        ADDRINFOEXA hint;
        PADDRINFOEXA results;
        int _errno;

        hint.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG;
        hint.ai_family = af;
        hint.ai_socktype = SOCK_STREAM;
        hint.ai_protocol = IPPROTO_TCP;
        hint.ai_addrlen = 0;
        hint.ai_addr = NULL;
        hint.ai_canonname = NULL;
        hint.ai_next = NULL;

        SASL_log((utils->conn, SASL_LOG_DEBUG, "xoauth2: lookup %s:%s with GetAddrInfoExA()", host_port_pair->host, host_port_pair->port_or_service));
        _errno = GetAddrInfoExA(
            host_port_pair->host,
            host_port_pair->port_or_service,
            NS_ALL,
            NULL,
            &hint,
            &results,
            NULL,
            NULL,
            NULL,
            NULL);
        info->addr.addr = results;
        if (0 != _errno) {
            char buf[1024] = "(unknown error)";
            ws2_strerror(_errno, buf, sizeof(buf));
            SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: GetAddrInfoExA() returned error %d (%s)", _errno, buf));
        }
        return addrinfo_error_to_sasl_code(_errno);
    }
}

static void xoauth2_plugin_win32_addr_info_free(const sasl_utils_t *utils, xoauth2_plugin_win32_addr_info_t *info)
{
    if (info->af != AF_UNIX) {
        FreeAddrInfoEx(info->addr.addr);
    }
    return;
}

static int xoauth2_plugin_win32_socket_read(const sasl_utils_t *utils, xoauth2_plugin_win32_socket_t *s, xoauth2_plugin_socket_iovec_t *iv, size_t nivs, unsigned *nread, unsigned minread, int timeout_ms)
{
    int err;
    unsigned total_sz;
    WSABUF *wsiv, *e_wsiv;

    /* Roll to (INT_MAX + 1) / 16 - 1 */
    if (nivs > (((uint32_t)-1) >> 5)) {
        nivs = (((uint32_t)-1) >> 5);
    }

    if (sizeof(WSABUF) * nivs < nivs) {
        return SASL_NOMEM;
    }
    wsiv = SASL_malloc(sizeof(WSABUF) * nivs);
    if (!wsiv) {
        return SASL_NOMEM;
    }

    {
        WSABUF *p_wsiv = wsiv;
        const xoauth2_plugin_socket_iovec_t *p, *e = iv + nivs;
        total_sz = 0;
        for (p = iv, e = iv + nivs; p < e; p++) {
            p_wsiv->len = p->iov_len;
            p_wsiv->buf = p->iov_base;
            if (total_sz + p->iov_len < total_sz) {
                total_sz = (((uint32_t)-1) >> 1);
                break;
            }
            if (total_sz > (((uint32_t)-1) >> 1)) {
                total_sz = (((uint32_t)-1) >> 1);
                break;
            }
            total_sz += p->iov_len;
            ++p_wsiv;
        }
        e_wsiv = p_wsiv;
    }

    if (!minread) {
        minread = total_sz;
    }

    *nread = 0;
    {
        WSABUF *p_wsiv = wsiv;
        WSAEVENT pol = WSACreateEvent();
        char buf[1024] = "(unknown error)";
        int first = 1;
        if (WSA_INVALID_EVENT == pol) {
            int _errno = WSAGetLastError();
            ws2_strerror(_errno, buf, sizeof(buf));
            SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: WSACreateEvent() returned error %d (%s)", _errno, buf));
            err = SASL_FAIL;
            goto out;
        }
        while (*nread < minread) {
            int wsc;
            int _errno;
            DWORD n;
            DWORD flags = 0;
            /* optimization; no polling on the first try */
            if (!first) {
                DWORD sig;
                if (SOCKET_ERROR == WSAEventSelect(s->s, pol, FD_READ)) {
                    _errno = WSAGetLastError();
                    WSACloseEvent(pol);
                    ws2_strerror(_errno, buf, sizeof(buf));
                    SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: WSAEventSelect() returned error %d (%s)", _errno, buf));
                    err = SASL_FAIL;
                    goto out;
                }
                sig = WaitForSingleObject(pol, timeout_ms < 0 ? INFINITE : timeout_ms);
                _errno = WSAGetLastError();
                switch (sig) {
                case WAIT_TIMEOUT:
                    WSACloseEvent(pol);
                    SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: timed out"));
                    err = SASL_FAIL;
                    goto out;
                case WAIT_OBJECT_0:
                    WSAResetEvent(pol);
                    break;
                default:
                    _errno = WSAGetLastError();
                    WSACloseEvent(pol);
                    ws2_strerror(_errno, buf, sizeof(buf));
                    SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: WaitForSingleObject() returned error %d (%s)", _errno, buf));
                    err = SASL_FAIL;
                    goto out;
                }
            }
            wsc = WSARecv(s->s, wsiv, (DWORD)nivs, &n, &flags, NULL, NULL);
            first = 0;
            if (SOCKET_ERROR == wsc) {
                int _errno = WSAGetLastError();
                if (WSAEWOULDBLOCK == _errno) {
                    continue;
                }
                WSACloseEvent(pol);
                ws2_strerror(_errno, buf, sizeof(buf));
                SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: WSARecv() returned error %d (%s)", _errno, buf));
                err = SASL_FAIL;
                goto out;
            }
            if (n == 0) {
                /* EOF */
                break;
            }
            *nread += n;
            if (p_wsiv >= e_wsiv) {
                WSACloseEvent(pol);
                SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: unexpected condition"));
                err = SASL_FAIL;
                goto out;
            }
            while (n > p_wsiv->len) {
                n -= p_wsiv->len;
                ++p_wsiv;
                --nivs;
            }
            *((unsigned char **)&p_wsiv->buf) += n;
            p_wsiv->len -= n;
        }
        WSACloseEvent(pol);
        err = SASL_OK;
    }
out:
    SASL_free(wsiv);
    return err;
}

static int xoauth2_plugin_win32_socket_write(const sasl_utils_t *utils, xoauth2_plugin_win32_socket_t *s, xoauth2_plugin_socket_iovec_t *iv, size_t nivs, unsigned *nwritten, int timeout_ms)
{
    int err;
    size_t total_sz;
    WSABUF *wsiv, *e_wsiv;

    /* Roll to (INT_MAX + 1) / 16 - 1 */
    if (nivs > (((uint32_t)-1) >> 5)) {
        nivs = (((uint32_t)-1) >> 5);
    }

    if (sizeof(WSABUF) * nivs < nivs) {
        return SASL_NOMEM;
    }
    wsiv = SASL_malloc(sizeof(WSABUF) * nivs);
    if (!wsiv) {
        return SASL_NOMEM;
    }

    {
        WSABUF *p_wsiv = wsiv;
        const xoauth2_plugin_socket_iovec_t *p, *e = iv + nivs;
        total_sz = 0;
        for (p = iv, e = iv + nivs; p < e; p++) {
            p_wsiv->len = p->iov_len;
            p_wsiv->buf = p->iov_base;
            if (total_sz + p->iov_len < total_sz) {
                total_sz = (((uint32_t)-1) >> 1);
                break;
            }
            if (total_sz > (((uint32_t)-1) >> 1)) {
                total_sz = (((uint32_t)-1) >> 1);
                break;
            }
            total_sz += p->iov_len;
            ++p_wsiv;
        }
        e_wsiv = p_wsiv;
    }

    *nwritten = 0;
    {
        WSABUF *p_wsiv = wsiv;
        WSAEVENT pol = WSACreateEvent();
        char buf[1024] = "(unknown error)";
        if (WSA_INVALID_EVENT == pol) {
            int _errno = WSAGetLastError();
            ws2_strerror(_errno, buf, sizeof(buf));
            SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: WSACreateEvent() returned error %d (%s)", _errno, buf));
            err = SASL_FAIL;
            goto out;
        }
        while (*nwritten < total_sz) {
            DWORD n;
            int _errno;
            {
                DWORD sig;
                if (SOCKET_ERROR == WSAEventSelect(s->s, pol, FD_WRITE)) {
                    _errno = WSAGetLastError();
                    WSACloseEvent(pol);
                    ws2_strerror(_errno, buf, sizeof(buf));
                    SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: WSAEventSelect() returned error %d (%s)", _errno, buf));
                    err = SASL_FAIL;
                    goto out;
                }
                sig = WaitForSingleObject(pol, timeout_ms < 0 ? INFINITE : timeout_ms);
                _errno = WSAGetLastError();
                switch (sig) {
                case WAIT_TIMEOUT:
                    WSACloseEvent(pol);
                    SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: timed out"));
                    err = SASL_FAIL;
                    goto out;
                case WAIT_OBJECT_0:
                    WSAResetEvent(pol);
                    break;
                default:
                    _errno = WSAGetLastError();
                    WSACloseEvent(pol);
                    ws2_strerror(_errno, buf, sizeof(buf));
                    SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: WaitForSingleObject() returned error %d (%s)", _errno, buf));
                    err = SASL_FAIL;
                    goto out;
                }
            }
            if (SOCKET_ERROR == WSASend(s->s, p_wsiv, (DWORD)nivs, &n, 0, NULL, NULL)) {
                int _errno = WSAGetLastError();
                if (WSAEWOULDBLOCK == _errno) {
                    continue;
                }
                WSACloseEvent(pol);
                ws2_strerror(_errno, buf, sizeof(buf));
                SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: WSASend() returned error %d (%s)", _errno, buf));
                err = SASL_FAIL;
                goto out;
            }
            *nwritten += n;
            if (p_wsiv >= e_wsiv) {
                WSACloseEvent(pol);
                SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: unexpected condition"));
                err = SASL_FAIL;
                goto out;
            }
            while (n > p_wsiv->len) {
                n -= p_wsiv->len;
                ++p_wsiv;
                --nivs;
            }
            *((unsigned char **)&p_wsiv->buf) += n;
            p_wsiv->len -= n;
        }
        WSACloseEvent(pol);
        err = SASL_OK;
    }
out:
    SASL_free(wsiv);
    return err;
}

void xoauth2_plugin_win32_socket_close(UNUSED(const sasl_utils_t *utils), xoauth2_plugin_win32_socket_t *s)
{
    if (INVALID_SOCKET == s->s) {
        return;
    }
    SASL_log((utils->conn, SASL_LOG_NOTE, "xoauth2: socket closed"));
    closesocket(s->s);
    s->s = INVALID_SOCKET;
}

static void xoauth2_plugin_win32_socket_cleanup(const sasl_utils_t *utils, xoauth2_plugin_win32_socket_t *s)
{
    xoauth2_plugin_win32_socket_close(utils, s);
    SASL_free(s);
}

static const xoauth2_plugin_socket_vtbl_t xoauth2_plugin_win32_socket_vtbl = {
    (xoauth2_plugin_socket_cleanup_fn_t)xoauth2_plugin_win32_socket_cleanup,
    (xoauth2_plugin_socket_close_fn_t)xoauth2_plugin_win32_socket_close,
    (xoauth2_plugin_socket_read_fn_t)xoauth2_plugin_win32_socket_read,
    (xoauth2_plugin_socket_write_fn_t)xoauth2_plugin_win32_socket_write
};

static int xoauth2_plugin_win32_socket_conv_af(enum xoauth2_plugin_af af)
{
    switch (af) {
    case XOAUTH2_PLUGIN_WIN32_AF_UNSPEC:
        return AF_UNSPEC;
    case XOAUTH2_PLUGIN_WIN32_AF_UNIX:
        return AF_UNIX;
    case XOAUTH2_PLUGIN_WIN32_AF_INET:
        return AF_INET;
    case XOAUTH2_PLUGIN_WIN32_AF_INET6:
        return AF_INET6;
    }
    return AF_UNSPEC;
}

int xoauth2_plugin_win32_socket_connect(const sasl_utils_t *utils, xoauth2_plugin_socket_t **retval, enum xoauth2_plugin_af _af, const char *addr, int timeout_ms)
{
    int err;
    int af = xoauth2_plugin_win32_socket_conv_af(_af);
    xoauth2_plugin_win32_addr_info_t info = { -1 };
    xoauth2_plugin_host_port_pair_t *pair = NULL;
    xoauth2_plugin_win32_socket_t *s;

    s = SASL_malloc(sizeof(xoauth2_plugin_win32_socket_t));
    if (!s) {
        return SASL_NOMEM;
    }
    s->vtbl = &xoauth2_plugin_win32_socket_vtbl;
    s->s = -1;

    if (af == AF_UNIX) {
        err = xoauth2_plugin_host_port_pair_new_no_port(utils, &pair, addr);
    } else {
        err = xoauth2_plugin_host_port_pair_new(utils, &pair, addr, "65321");
    }
    if (SASL_OK != err) {
        goto out;
    }
    err = xoauth2_plugin_win32_addr_info_lookup(utils, &info, af, pair);
    if (SASL_OK != err) {
        goto out;
    }

    {
        ADDRINFOEXA tmp;
        PADDRINFOEXA addr;

        if (AF_UNIX == info.af) {
#ifdef WIN32_UDS
            tmp.ai_family = info.af;
            tmp.ai_protocol = AF_INET;
            tmp.ai_addr = (struct sockaddr *)&info.addr.sun;
            tmp.ai_addrlen = sizeof(info.addr.sun);
            tmp.ai_next = NULL;
            addr = &tmp;
#else
            SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: unsupported address family"));
            err = SASL_FAIL;
            goto out;
#endif 
        } else {
            addr = info.addr.addr;
        }
        for (; addr; addr = addr->ai_next) {
            char buf[1024] = "(unknown error)";
            int _errno;
            const ULONG nonzero = 1;
            WSAEVENT pol;
            DWORD sig;
            s->s = WSASocket(addr->ai_family, SOCK_STREAM, addr->ai_protocol, NULL, 0, WSA_FLAG_OVERLAPPED);
            if (INVALID_SOCKET == s->s) {
                _errno = WSAGetLastError();
                ws2_strerror(_errno, buf, sizeof(buf));
                SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: WSASocket() returned error %d (%s)", _errno, buf));
                err = SASL_FAIL;
                goto out;
            }
            /*{
                DWORD dummy;
                if (SOCKET_ERROR == WSAIoctl(s->s, FIONBIO, (LPVOID)&nonzero, sizeof(nonzero), NULL, 0, &dummy, NULL, NULL)) {
                    _errno = WSAGetLastError();
                    closesocket(s->s);
                    ws2_strerror(_errno, buf, sizeof(buf));
                    SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: WSAIoctl() returned error %d (%s)", _errno, buf));
                    err = SASL_FAIL;
                    goto out;
                }
            }*/
            pol = WSACreateEvent();
            if (WSA_INVALID_EVENT == pol) {
                _errno = WSAGetLastError();
                closesocket(s->s);
                ws2_strerror(_errno, buf, sizeof(buf));
                SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: WSACreateEvent() returned error %d (%s)", _errno, buf));
                err = SASL_FAIL;
                goto out;
            }
            if (SOCKET_ERROR == WSAEventSelect(s->s, pol, FD_CONNECT)) {
                _errno = WSAGetLastError();
                WSACloseEvent(pol); 
                closesocket(s->s);
                ws2_strerror(_errno, buf, sizeof(buf));
                SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: WSAEventSelect() returned error %d (%s)", _errno, buf));
                err = SASL_FAIL;
                goto out;
            }
            if (SOCKET_ERROR == WSAConnect(s->s, addr->ai_addr, addr->ai_addrlen, NULL, NULL, NULL, NULL)) {
                _errno = WSAGetLastError();
                if (WSAEWOULDBLOCK != _errno && WSAEINPROGRESS != _errno) {
                    WSACloseEvent(pol); 
                    closesocket(s->s);
                    ws2_strerror(_errno, buf, sizeof(buf));
                    SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: WSAConnect() returned error %d (%s)", _errno, buf));
                    continue;
                }
            }
            sig = WaitForSingleObject(pol, timeout_ms < 0 ? INFINITE : timeout_ms);
            _errno = WSAGetLastError();
            WSACloseEvent(pol);
            switch (sig) {
            case WAIT_TIMEOUT:
                closesocket(s->s);
                SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: WSAConnect() timed out"));
                err = SASL_FAIL;
                continue;
            case WAIT_OBJECT_0:
                err = SASL_OK;
                break;
            default:
                WSACloseEvent(pol); 
                closesocket(s->s);
                ws2_strerror(_errno, buf, sizeof(buf));
                SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: WaitForSingleObject() returned error %d (%s)", _errno, buf));
                err = SASL_FAIL;
                goto out;
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
        xoauth2_plugin_win32_addr_info_free(utils, &info);
    }
    if (SASL_OK != err) {
        xoauth2_plugin_win32_socket_cleanup(utils, s);
    }
    return err;
}

int xoauth2_plugin_win32_socket_setup()
{
    WSADATA dummy;
    int _errno = WSAStartup(WINSOCK_VERSION, &dummy);
    if (0 != _errno) {
        char buf[1024];
        ws2_strerror(_errno, buf, sizeof(buf));
        fprintf(stderr, "xoauth2: WSAStartup() failed (%s)\n", buf);
        return SASL_FAIL;
    }
    return SASL_OK;
}

void xoauth2_plugin_win32_socket_teardown()
{
    WSACleanup();
}
