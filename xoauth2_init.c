#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "xoauth2_plugin.h"

#ifdef WIN32
BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
    }
    return TRUE;
}
#endif

SASLPLUGINAPI int sasl_client_plug_init(const sasl_utils_t *utils, int maxversion, int *out_version, sasl_client_plug_t **pluglist, int *plugcount)
{
    xoauth2_client_plugin_init(utils, maxversion, out_version, pluglist, plugcount);
}

SASLPLUGINAPI int sasl_server_plug_init(const sasl_utils_t *utils, int maxversion, int *out_version, sasl_server_plug_t **pluglist, int *plugcount)
{
    xoauth2_server_plugin_init(utils, maxversion, out_version, pluglist, plugcount);
}
