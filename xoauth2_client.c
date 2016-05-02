#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include "xoauth2_plugin.h"

static int xoauth2_plugin_client_mech_new(
        void *glob_context __attribute__((unused)),
        sasl_client_params_t *params,
        void **conn_context)
{
    return SASL_OK;
}

static int xoauth2_plugin_client_mech_step(
        void *conn_context,
        sasl_client_params_t *params,
        const char *serverin __attribute__((unused)),
        unsigned serverinlen __attribute__((unused)),
        sasl_interact_t **prompt_need,
        const char **clientout,
        unsigned *clientoutlen,
        sasl_out_params_t *oparams)
{
}

static void xoauth2_plugin_client_mech_dispose(
        void *conn_context,
        const sasl_utils_t *utils)
{
}

static sasl_client_plug_t xoauth2_client_plugins[] = 
{
    {
        "XOAUTH2",                          /* mech_name */
        0,                                  /* max_ssf */
        SASL_SEC_NOANONYMOUS
        | SASL_SEC_PASS_CREDENTIALS,        /* security_flags */
        SASL_FEAT_WANT_CLIENT_FIRST,        /* features */
        NULL,                               /* required_prompts */
        NULL,                               /* glob_context */
        &xoauth2_plugin_client_mech_new,    /* mech_new */
        &xoauth2_plugin_client_mech_step,   /* mech_step */
        &xoauth2_plugin_client_mech_dispose,/* mech_dispose */
        NULL,                               /* mech_free */
        NULL,                               /* idle */
        NULL,                               /* spare */
        NULL                                /* spare */
    }
};

int xoauth2_client_plug_init(
        sasl_utils_t *utils,
        int maxversion,
        int *out_version,
        sasl_client_plug_t **pluglist,
        int *plugcount)
{
    if (maxversion < SASL_CLIENT_PLUG_VERSION) {
        SETERROR(utils, "xoauth2: version mismatch");
        return SASL_BADVERS;
    }
    *out_version = SASL_CLIENT_PLUG_VERSION;
    *pluglist = xoauth2_client_plugins;
    *plugcount = sizeof(xoauth2_client_plugins) / sizeof(*xoauth2_client_plugins);
    return SASL_OK;
}

