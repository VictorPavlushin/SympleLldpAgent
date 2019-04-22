#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#include <winsdkver.h>
#define _WIN32_WINNT 0x0501
#include <sdkddkver.h>
#include <iostream>
#include <winsock2.h>
#include <windows.h>
#include <Winsvc.h>
#include <ctime>
#include <netioapi.h>
#include <iphlpapi.h>
#pragma comment(lib, "IPHLPAPI.lib") 
#pragma comment(lib, "ws2_32.lib")
#include <atlbase.h>
#include <vector>
#include <iomanip>
#include <algorithm>

#define SVCNAME TEXT("SimpleLldpAgent")

#include <stdio.h>

#include "dpcap.h"

using namespace std;


void md_install_service();
void md_service_control(DWORD dwControl);
void md_service_main(DWORD argc, char** argv);
void md_remove_service();


void interrupt();
void loop();

void _dbg_cfg(bool enabled);
basic_ostream<char>* _dbg(const char* func, int line);

#define dbg (*_dbg(__FUNCTION__, __LINE__))

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))
