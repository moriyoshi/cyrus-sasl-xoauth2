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
#include "config.h"
#endif

#include <stdio.h>
#include "xoauth2_plugin.h"
#include "xoauth2_socket.h"

#if XOAUTH2_WIN32

BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        xoauth2_plugin_socket_teardown();
        break;
    }
    return TRUE;
}
#endif

SASLPLUGINAPI int sasl_client_plug_init(const sasl_utils_t *utils, int maxversion, int *out_version, sasl_client_plug_t **pluglist, int *plugcount)
{
    int err;
    err = xoauth2_plugin_socket_setup();
    if (SASL_OK != err) {
        return err;
    }
    return xoauth2_client_plug_init(utils, maxversion, out_version, pluglist, plugcount);
}

SASLPLUGINAPI int sasl_server_plug_init(const sasl_utils_t *utils, int maxversion, int *out_version, sasl_server_plug_t **pluglist, int *plugcount)
{
    int err;
    err = xoauth2_plugin_socket_setup();
    if (SASL_OK != err) {
        return err;
    }
    return xoauth2_server_plug_init(utils, maxversion, out_version, pluglist, plugcount);
}
