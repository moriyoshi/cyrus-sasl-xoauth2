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

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <string.h>
#include <errno.h>
#include <stdio.h>

#include "xoauth2_token_conv.h"
#include "xoauth2_socket.h"

static const char signature[] = { 0x81, 0x9d, 0x74, 0x13 };
static const int32_t version = 1;

static int xoauth2_plugin_token_conv_initiate(const sasl_utils_t *utils, xoauth2_plugin_token_conv_t *token_conv)
{
    int err;
    xoauth2_plugin_socket_t *s;

    if (token_conv->s) {
        return SASL_FAIL;
    }

    err = xoauth2_plugin_socket_connect(utils, &s, token_conv->family.buf, token_conv->addr.buf, token_conv->settings->connect_timeout);
    if (SASL_OK != err) {
        return err;
    }

    /* send signature and version */
    {
        const unsigned char ver_buf[4] = {
            (version >> 24) & 0xff,
            (version >> 16) & 0xff,
            (version >>  8) & 0xff,
            version         & 0xff,
        };
        xoauth2_plugin_socket_iovec_t iv[] = {
            { (char *)signature, 4 },
            { (char *)ver_buf, 4 }
        };
        unsigned n;
        err = xoauth2_plugin_socket_write(utils, s, iv, sizeof(iv) / sizeof(*iv), &n, token_conv->settings->write_timeout);
        if (SASL_OK == err && n != 8) {
            err = SASL_FAIL;
        }
        if (SASL_OK != err) {
            goto out;
        }
    }

    /* receive signature and server version */
    {
        unsigned char buf[8];
        xoauth2_plugin_socket_iovec_t iv[] = { { buf, sizeof(buf) } };
        unsigned n;
        int32_t ver;
        err = xoauth2_plugin_socket_read(utils, s, iv, sizeof(iv) / sizeof(*iv), &n, 0, token_conv->settings->read_timeout);
        if (SASL_OK == err && n != 8) {
            err = SASL_FAIL;
        }
        if (SASL_OK != err) {
            goto out;
        }
        /* verify signature */
        SASL_log((utils->conn, SASL_LOG_DEBUG, "signature: %02x %02x %02x %02x %02x %02x %02x %02x", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]));
        if (memcmp(&buf[0], signature, sizeof(signature)) != 0) {
            SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: signature mismatch"));
            err = SASL_FAIL;
            goto out;
        }
        /* verify version */
        ver = (((unsigned int)buf[4]) << 24)
            | (((unsigned int)buf[5]) << 16)
            | (((unsigned int)buf[6]) <<  8)
            | ((unsigned int)buf[7]);
        SASL_log((utils->conn, SASL_LOG_DEBUG, "version: client=%d, server=%d", version, ver));
        if (version < ver) {
            SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: server version too old"));
            err = SASL_FAIL;
            goto out;
        }
    }
out:
    if (SASL_OK != err) {
        xoauth2_plugin_socket_cleanup(utils, s);
    } else {
        token_conv->s = s;
    }
    return err;
}

static int xoauth2_plugin_token_conv_send_packet(const sasl_utils_t *utils, xoauth2_plugin_token_conv_t *token_conv, const xoauth2_plugin_socket_iovec_t *ivs, size_t nivs)
{
    int err;
    size_t total_len = 0;

    if (nivs > (((uint32_t)-1) >> 5)) {
        SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: too long packet"));
        return SASL_FAIL;
    }

    {
        const xoauth2_plugin_socket_iovec_t *p, *e = ivs + nivs;
        for (p = ivs; p < e; p++) {
            size_t new_total_len = total_len + p->iov_len;
            if (new_total_len < total_len) {
                SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: too long packet"));
                return SASL_FAIL;
            }
            total_len = new_total_len;
        }
        if (total_len >= (((uint32_t)-1) >> 1)) {
            SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: too long packet"));
            return SASL_FAIL;
        }
    }

    {
        unsigned char buf[4] = {
            (unsigned char)(total_len >> 24),
            (unsigned char)(total_len >> 16),
            (unsigned char)(total_len >> 8),
            (unsigned char)total_len
        };
        xoauth2_plugin_socket_iovec_t *_ivs;
        unsigned nwritten;

        _ivs = SASL_malloc(sizeof(xoauth2_plugin_socket_iovec_t) * (nivs + 1));
        if (!_ivs) {
            return SASL_NOMEM;
        }

        /* insert packet length */
        _ivs[0].iov_base = buf;
        _ivs[0].iov_len = sizeof(buf);
        memcpy(_ivs + 1, ivs, sizeof(xoauth2_plugin_socket_iovec_t) * nivs);

        err = xoauth2_plugin_socket_write(utils, token_conv->s, _ivs, nivs + 1, &nwritten, token_conv->settings->write_timeout);
        SASL_free(_ivs);
        if (SASL_OK != err) {
            return err;
        }
    }
    return SASL_OK;
}

static int xoauth2_plugin_token_conv_read_packet(const sasl_utils_t *utils, xoauth2_plugin_token_conv_t *token_conv, xoauth2_plugin_str_t *retval, unsigned *sz)
{
    int err;
    unsigned _sz, off, nread;
    err = xoauth2_plugin_str_alloc(utils, retval, retval->len + 1024);
    if (SASL_OK != err) {
        return err;
    }

    off = 0;
    *sz = 0;
    {
        unsigned char buf[4];
        xoauth2_plugin_socket_iovec_t iv[] = { { buf, sizeof(buf) }, { retval->buf + retval->len, retval->size - retval->len } };
        err = xoauth2_plugin_socket_read(utils, token_conv->s, iv, sizeof(iv) / sizeof(*iv), &nread, sizeof(buf), token_conv->settings->read_timeout);
        if (SASL_OK != err) {
            return err;
        }
        if (nread < 4) {
            SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: unexpected EOF (at least 4 bytes wanted, got %u bytes)", nread));
            return SASL_BADPROT;
        }
        _sz = (((unsigned)buf[0]) << 24)
            | (((unsigned)buf[1]) << 16)
            | (((unsigned)buf[2]) << 8)
            | (unsigned)buf[3];
        SASL_log((utils->conn, SASL_LOG_DEBUG, "xoauth2: packet_size=%u", _sz));
        if (_sz > (((unsigned int)-1) >> 1)) {
            SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: too large packet (the peer tolds us %u bytes follow)", _sz));
            return SASL_BADPROT;
        }
        if (_sz + retval->len < _sz) {
            SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: too large packet"));
            return SASL_NOMEM;
        }
        *sz = _sz;
        off += nread - 4;
        if (off == _sz) {
            retval->len += off;
            return SASL_OK;
        }
    }
    err = xoauth2_plugin_str_alloc(utils, retval, retval->len + (_sz - off));
    if (SASL_OK != err) {
        return err;
    }
    {
        xoauth2_plugin_socket_iovec_t iv[] = { { retval->buf + retval->len + off, retval->size - retval->len - off } };
        err = xoauth2_plugin_socket_read(utils, token_conv->s, iv, sizeof(iv) / sizeof(*iv), &nread, 0, token_conv->settings->read_timeout);
        if (SASL_OK != err) {
            return err;
        }
    }
    retval->len += *sz;
    return SASL_OK;
}

static void xoauth2_plugin_token_conv_close_socket(const sasl_utils_t *utils, xoauth2_plugin_token_conv_t *token_conv)
{
    if (token_conv->s) {
        xoauth2_plugin_socket_t *s = token_conv->s;
        token_conv->s = 0;
        xoauth2_plugin_socket_cleanup(utils, s);
    }
}

int xoauth2_plugin_token_conv_retrieve_access_token(const sasl_utils_t *utils, xoauth2_plugin_token_conv_t *token_conv, xoauth2_plugin_str_t *token, const char *authid, unsigned authid_len)
{
    int err;
    unsigned token_len;

    if (!token_conv->s) {
        err = xoauth2_plugin_token_conv_initiate(utils, token_conv);
        if (SASL_OK != err) {
            return err;
        }
    }

    {
        const xoauth2_plugin_socket_iovec_t ivs[] = {
            { "authid", sizeof("authid") },
            { (void *)authid, authid_len }
        };

        err = xoauth2_plugin_token_conv_send_packet(utils, token_conv, ivs, sizeof(ivs) / sizeof(*ivs));
        if (SASL_OK != err) {
            xoauth2_plugin_token_conv_close_socket(utils, token_conv);
            return err;
        }
    }

    token->len = 0;
    err = xoauth2_plugin_token_conv_read_packet(utils, token_conv, token, &token_len);
    if (SASL_OK != err) {
        xoauth2_plugin_token_conv_close_socket(utils, token_conv);
        return err;
    }

    return SASL_OK;
}

void xoauth2_plugin_token_conv_free(const sasl_utils_t *utils, xoauth2_plugin_token_conv_t *token_conv)
{
    if (token_conv->s) {
        xoauth2_plugin_socket_cleanup(utils, token_conv->s);
    }
    xoauth2_plugin_str_free(utils, &token_conv->addr);
    xoauth2_plugin_str_free(utils, &token_conv->family);
}

int xoauth2_plugin_token_conv_init(const sasl_utils_t *utils, xoauth2_plugin_token_conv_t *token_conv, const xoauth2_plugin_token_conv_settings_t *settings, const char *family_and_addr)
{
    int err;
    const char *p;
    p = strchr(family_and_addr, ':');
    if (!p) {
        SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2: invalid connection string: %s", family_and_addr));
        return SASL_FAIL;
    }

    err = xoauth2_plugin_str_init(utils, &token_conv->family);
    if (SASL_OK != err) {
        return err;
    }

    err = xoauth2_plugin_str_append(utils, &token_conv->family, family_and_addr, p - family_and_addr);
    if (SASL_OK != err) {
        xoauth2_plugin_str_free(utils, &token_conv->family);
        return err;
    }

    err = xoauth2_plugin_str_init(utils, &token_conv->addr);
    if (SASL_OK != err) {
        xoauth2_plugin_str_free(utils, &token_conv->family);
        return err;
    }

    err = xoauth2_plugin_str_append(utils, &token_conv->addr, p + 1, strlen(family_and_addr) - (p - family_and_addr - 1));
    if (SASL_OK != err) {
        xoauth2_plugin_str_free(utils, &token_conv->addr);
        xoauth2_plugin_str_free(utils, &token_conv->family);
        return err;
    }

    token_conv->settings = settings;
    token_conv->s = NULL;

    return SASL_OK;
}
