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
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "xoauth2_plugin.h"
#include "xoauth2_token_conv.h"

typedef struct _xoauth2_plugin_client_global_context_t {
    int token_conv_enabled;
    xoauth2_plugin_token_conv_t token_conv;
} xoauth2_plugin_client_global_context_t;

static const xoauth2_plugin_token_conv_settings_t settings = {
    2000, /* connect */
    2000, /* write */
    2000  /* read */
};

static int xoauth2_plugin_client_global_context_init(
        const sasl_utils_t *utils,
        xoauth2_plugin_client_global_context_t *glob_context)
{
    glob_context->token_conv_enabled = 0;
    {
        const char *token_conv_conn_spec = getenv("SASL_XOAUTH2_CLIENT_TOKEN_CONV");

        if (token_conv_conn_spec && strlen(token_conv_conn_spec) != 0) {
            glob_context->token_conv_enabled = 1;
            return xoauth2_plugin_token_conv_init(utils, &glob_context->token_conv, &settings, token_conv_conn_spec);
        }
    }
    return SASL_OK;
}

static void xoauth2_plugin_client_global_context_free(
        const sasl_utils_t *utils,
        xoauth2_plugin_client_global_context_t *glob_context)
{
    if (glob_context->token_conv_enabled) {
        xoauth2_plugin_token_conv_free(utils, &glob_context->token_conv);
    }
}

static int xoauth2_plugin_client_mech_new(
        void *glob_context,
        sasl_client_params_t *params,
        void **pcontext)
{
    int err;
    const sasl_utils_t *utils = params->utils;
    xoauth2_plugin_client_context_t *context;

    context = SASL_malloc(sizeof(*context));
    if (!context) {
        SASL_seterror((utils->conn, 0, "Failed to allocate memory"));
        return SASL_NOMEM;
    }

    context->state = 0;
    context->resp.buf = NULL;
    context->glob_context = glob_context;
    err = xoauth2_plugin_str_init(utils, &context->outbuf);
    if (err != SASL_OK) {
        SASL_free(context);
        return err;
    }
    err = xoauth2_plugin_str_init(utils, &context->token);
    if (err != SASL_OK) {
        xoauth2_plugin_str_free(utils, &context->outbuf);
        SASL_free(context);
        return err;
    }
    *pcontext = context;
    return SASL_OK;
}

static int build_client_response(const sasl_utils_t *utils, xoauth2_plugin_str_t *outbuf, xoauth2_plugin_auth_response_t *resp)
{
    int err;
    err = xoauth2_plugin_str_append(utils, outbuf, "user=", 5);
    if (err != SASL_OK) {
        return err;
    }
    err = xoauth2_plugin_str_append(utils, outbuf, resp->authid, resp->authid_len);
    if (err != SASL_OK) {
        return err;
    }
    err = xoauth2_plugin_str_append(utils, outbuf, "\1", 1);
    if (err != SASL_OK) {
        return err;
    }
    err = xoauth2_plugin_str_append(utils, outbuf, "auth=", 5);
    if (err != SASL_OK) {
        return err;
    }
    err = xoauth2_plugin_str_append(utils, outbuf, resp->token_type, resp->token_type_len);
    if (err != SASL_OK) {
        return err;
    }
    err = xoauth2_plugin_str_append(utils, outbuf, " ", 1);
    if (err != SASL_OK) {
        return err;
    }
    err = xoauth2_plugin_str_append(utils, outbuf, resp->token, resp->token_len);
    if (err != SASL_OK) {
        return err;
    }
    err = xoauth2_plugin_str_append(utils, outbuf, "\1\1", 2);
    if (err != SASL_OK) {
        return err;
    }
    return SASL_OK;
}

static sasl_interact_t *find_prompt(sasl_interact_t *prompts, unsigned id)
{
    sasl_interact_t *p;
    for (p = prompts; p->id != SASL_CB_LIST_END; ++p) {
        if (p->id == id) {
            return p;
        }
    }
    return NULL;
}

static int get_prompt_value(sasl_interact_t *prompts, unsigned id, const char **result, unsigned *result_len)
{
    int err;
    sasl_interact_t *prompt;
    prompt = find_prompt(prompts, id);
    if (!prompt) {
        return SASL_FAIL;
    }

    *result = (const char *)prompt->result;
    *result_len = prompt->len;

    return SASL_OK;
}

static int get_cb_value(const sasl_utils_t *utils, unsigned id, const char **result, unsigned *result_len)
{
    int err;
    switch (id) {
    case SASL_CB_PASS:
        {
            sasl_getsecret_t *cb;
            void *cb_ctx;
            sasl_secret_t *secret;
            err = utils->getcallback(utils->conn, id, (sasl_callback_ft *)&cb, &cb_ctx);
            if (err != SASL_OK) {
                return err;
            }
            err = cb(utils->conn, cb_ctx, id, &secret);
            if (err != SASL_OK) {
                return err;
            }
            if (secret->len >= UINT_MAX) {
                return SASL_BADPROT;
            }
            *result = (const char *)secret->data;
            *result_len = secret->len;
        }
        break;
    case SASL_CB_USER:
    case SASL_CB_AUTHNAME:
    case SASL_CB_LANGUAGE:
    case SASL_CB_CNONCE:
        {
            sasl_getsimple_t *cb;
            void *cb_ctx;
            err = utils->getcallback(utils->conn, id, (sasl_callback_ft *)&cb, &cb_ctx);
            if (err != SASL_OK) {
                return err;
            }
            err = cb(cb_ctx, id, result, result_len);
        }
        break;
    default:
        err = SASL_FAIL;
    }
    return err;
}

static int xoauth2_plugin_client_mech_step1(
        void *_context,
        sasl_client_params_t *params,
        const char *serverin,
        unsigned serverin_len,
        sasl_interact_t **prompt_need,
        const char **clientout,
        unsigned *clientout_len,
        sasl_out_params_t *oparams)
{
    const sasl_utils_t *utils = params->utils;
    xoauth2_plugin_client_context_t *context = _context;
    int err = SASL_OK;
    xoauth2_plugin_auth_response_t resp;
    int authid_wanted = 1;
    int password_wanted = 1;
    sasl_interact_t *prompt_returned = NULL;

    *clientout = NULL;
    *clientout_len = 0;

    SASL_log((utils->conn, SASL_LOG_DEBUG, "xoauth2: step1"));

    if (!context) {
        return SASL_BADPROT;
    }

    if (prompt_need && *prompt_need) {
        if (SASL_OK == get_prompt_value(*prompt_need, SASL_CB_AUTHNAME, (const char **)&resp.authid, &resp.authid_len)) {
            authid_wanted = 0;
        }
    }

    if (authid_wanted) {
        err = get_cb_value(utils, SASL_CB_AUTHNAME, (const char **)&resp.authid, &resp.authid_len);
        switch (err) {
        case SASL_OK:
            authid_wanted = 0;
            break;
        case SASL_INTERACT:
            break;
        default:
            goto out;
        }
    }

    if (prompt_need && *prompt_need) {
        if (SASL_OK == get_prompt_value(*prompt_need, SASL_CB_PASS, (const char **)&resp.token, &resp.token_len)) {
            password_wanted = 0;
        }
    }

    if (password_wanted) {
        err = get_cb_value(utils, SASL_CB_PASS, (const char **)&resp.token, &resp.token_len);
        switch (err) {
        case SASL_OK:
            password_wanted = 0;
            break;
        case SASL_INTERACT:
            break;
        default:
            goto out;
        }
    }

    if (context->glob_context->token_conv_enabled &&
        !authid_wanted &&
            (
                password_wanted
                || resp.token_len == 0
                || (resp.token_len == 1 && strncmp(resp.token, "-", 1) == 0)
            )) {
        err = xoauth2_plugin_token_conv_retrieve_access_token(
                utils,
                &context->glob_context->token_conv,
                &context->token,
                resp.authid,
                resp.authid_len);
        if (SASL_OK != err) {
            goto out;
        }
        resp.token = context->token.buf;
        resp.token_len = context->token.len;
        password_wanted = 0;
    }

    if (!authid_wanted && !password_wanted) {
        err = params->canon_user(
                utils->conn, resp.authid, resp.authid_len,
                SASL_CU_AUTHID | SASL_CU_AUTHZID, oparams);
        if (err != SASL_OK) {
            goto out;
        }
        resp.token_type = "Bearer";
        resp.token_type_len = 6;
        err = build_client_response(utils, &context->outbuf, &resp);
        if (err != SASL_OK) {
            goto out;
        }
        *clientout = context->outbuf.buf;
        *clientout_len = context->outbuf.len;
        context->state = 1;
        err = SASL_CONTINUE;
    } else {
        const size_t prompts = authid_wanted + password_wanted + 1;
        sasl_interact_t *p;
        prompt_returned = SASL_malloc(sizeof(sasl_interact_t) * prompts);
        if (!prompt_returned) {
            SASL_log((utils->conn, SASL_LOG_ERR, "failed to allocate buffer"));
            err = SASL_NOMEM;
            goto out;
        }
        memset(prompt_returned, 0, sizeof(sasl_interact_t) * prompts);
        p = prompt_returned;
        if (authid_wanted) {
            p->id = SASL_CB_AUTHNAME;
            p->challenge = "Authentication Name";
            p->prompt = "Authentication ID";
            p->defresult = NULL;
            ++p;
        }

        if (password_wanted) {
            p->id = SASL_CB_PASS;
            p->challenge = "Password";
            p->prompt = "Password";
            p->defresult = NULL;
            ++p;
        }
        p->id = SASL_CB_LIST_END;
        p->challenge = NULL;
        p->prompt = NULL;
        p->defresult = NULL;
        err = SASL_INTERACT;
    }
out:
    if (prompt_need) {
        if (*prompt_need) {
            SASL_free(*prompt_need);
            *prompt_need = NULL;
        }
        if (prompt_returned) {
            *prompt_need = prompt_returned;
        }
    }
    return err;
}

static int xoauth2_plugin_client_mech_step2(
        void *_context,
        sasl_client_params_t *params,
        const char *serverin,
        unsigned serverin_len,
        sasl_interact_t **prompt_need,
        const char **clientout,
        unsigned *clientout_len,
        sasl_out_params_t *oparams)
{
    const sasl_utils_t *utils = params->utils;
    xoauth2_plugin_client_context_t *context = _context;
    int err = SASL_OK;
    xoauth2_plugin_auth_response_t resp;

    *clientout = NULL;
    *clientout_len = 0;

    SASL_log((utils->conn, SASL_LOG_DEBUG, "xoauth2: step2"));

    if (!context) {
        return SASL_BADPROT;
    }

    *clientout = "";
    *clientout_len = 0;

    context->state = 2;
    return SASL_OK;
}


static int xoauth2_plugin_client_mech_step(
        void *_context,
        sasl_client_params_t *params,
        const char *serverin,
        unsigned serverin_len,
        sasl_interact_t **prompt_need,
        const char **clientout,
        unsigned *clientout_len,
        sasl_out_params_t *oparams)
{
    xoauth2_plugin_client_context_t *context = _context;

    switch (context->state) {
    case 0:
        return xoauth2_plugin_client_mech_step1(
            context,
            params,
            serverin,
            serverin_len,
            prompt_need,
            clientout,
            clientout_len,
            oparams
        );
    case 1:
        return xoauth2_plugin_client_mech_step2(
            context,
            params,
            serverin,
            serverin_len,
            prompt_need,
            clientout,
            clientout_len,
            oparams
        );
    }
    return SASL_BADPROT;
}

static void xoauth2_plugin_client_mech_dispose(
        void *_context,
        const sasl_utils_t *utils)
{
    xoauth2_plugin_client_context_t *context = _context;

    if (!context) {
        return;
    }

    xoauth2_plugin_str_free(utils, &context->token);
    xoauth2_plugin_str_free(utils, &context->outbuf);
    SASL_free(context);
}

static void xoauth2_plugin_client_mech_free(void *glob_context, const sasl_utils_t *utils)
{
    xoauth2_plugin_client_global_context_free(utils, (xoauth2_plugin_client_global_context_t *)glob_context);
}

static sasl_client_plug_t xoauth2_client_plugins[] = 
{
    {
        "XOAUTH2",                          /* mech_name */
        0,                                  /* max_ssf */
        SASL_SEC_NOANONYMOUS
        | SASL_SEC_PASS_CREDENTIALS,        /* security_flags */
        SASL_FEAT_WANT_CLIENT_FIRST
        | SASL_FEAT_ALLOWS_PROXY,           /* features */
        NULL,                               /* required_prompts */
        NULL,                               /* glob_context */
        &xoauth2_plugin_client_mech_new,    /* mech_new */
        &xoauth2_plugin_client_mech_step,   /* mech_step */
        &xoauth2_plugin_client_mech_dispose,/* mech_dispose */
        &xoauth2_plugin_client_mech_free,   /* mech_free */
        NULL,                               /* idle */
        NULL,                               /* spare */
        NULL                                /* spare */
    }
};

static xoauth2_plugin_client_global_context_t xoauth2_client_global_context;

int xoauth2_client_plug_init(
        const sasl_utils_t *utils,
        int maxversion,
        int *out_version,
        sasl_client_plug_t **pluglist,
        int *plugcount)
{
    if (maxversion < SASL_CLIENT_PLUG_VERSION) {
        SASL_seterror((utils->conn, 0, "xoauth2: version mismatch"));
        return SASL_BADVERS;
    }

    {
        int err = xoauth2_plugin_client_global_context_init(utils, &xoauth2_client_global_context);
        if (SASL_OK != err) {
            SASL_seterror((utils->conn, 0, "xoauth2: global context initialization failed (%d)", err));
            return SASL_FAIL;
        }
        xoauth2_client_plugins[0].glob_context = &xoauth2_client_global_context;
    }

    *out_version = SASL_CLIENT_PLUG_VERSION;
    *pluglist = xoauth2_client_plugins;
    *plugcount = sizeof(xoauth2_client_plugins) / sizeof(*xoauth2_client_plugins);

    return SASL_OK;
}
