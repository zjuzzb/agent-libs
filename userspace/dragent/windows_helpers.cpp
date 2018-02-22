#include <Windows.h>
#include <Iphlpapi.h>
#include <atomic>
#include <memory>
#include <set>
#include <map>
#include <string>
using namespace std;
#include "Poco/File.h"
#include "Poco/Path.h"
#include "windows_helpers.h"
using namespace Poco;

string windows_helpers::get_machine_first_mac_address()
{
    PIP_ADAPTER_INFO AdapterInfo;
    DWORD dwBufLen = sizeof(AdapterInfo);
    char *mac_addr = (char*)malloc(17);

    AdapterInfo = (IP_ADAPTER_INFO *) malloc(sizeof(IP_ADAPTER_INFO));
    if(AdapterInfo == NULL) 
    {
        return "00:00:00:00:00:00";
    }

    // Make an initial call to GetAdaptersInfo to get the necessary size into the dwBufLen     variable
    if(GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) 
    {
        free(AdapterInfo);

        AdapterInfo = (IP_ADAPTER_INFO *) malloc(dwBufLen);
        if(AdapterInfo == NULL) 
        {
            return "00:00:00:00:00:00";
        }
    }

    if(GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR) 
    {
        PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;// Contains pointer to current adapter info
        do {
            sprintf(mac_addr, "%02X:%02X:%02X:%02X:%02X:%02X",
                pAdapterInfo->Address[0], pAdapterInfo->Address[1],
                pAdapterInfo->Address[2], pAdapterInfo->Address[3],
                pAdapterInfo->Address[4], pAdapterInfo->Address[5]);
        
            free(AdapterInfo);
            return mac_addr;
        }while(pAdapterInfo);
    }

    free(AdapterInfo);
    return "00:00:00:00:00:00";
}

string windows_helpers::get_executable_parent_dir()
{
	char exename[MAX_PATH];

	if(GetModuleFileName(NULL, exename, ARRAYSIZE(exename)) == 0)
	{
		return "";
	}
	
	string exe(exename);

	size_t dpos = exe.rfind('\\');
	if(dpos != string::npos)
	{
		string exedir = exe.substr(0, dpos);

		dpos = exedir.rfind('\\');
		if(dpos != string::npos)
		{
			return exedir.substr(0, dpos);
		}
	}

	return "";
}

bool windows_helpers::is_parent_service_running()
{
	if(m_service_file_name == "")
	{
		m_service_file_name = Path(get_executable_parent_dir()).append("logs").append("service_running").toString();
	}

	FILE* h = fopen(m_service_file_name.c_str(), "r");
//	HANDLE h = OpenEvent(READ_CONTROL, FALSE, TEXT("Global\\__DragentServiceRunning"));
	if(h != NULL)
	{
//		CloseHandle(h);
		fclose(h);
		return true;
	}

	return false;
}
