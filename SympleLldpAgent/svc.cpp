#include "Header.h"

static SERVICE_STATUS sStatus;
static SERVICE_STATUS_HANDLE hServiceStatus = 0;
#define COUNTOF(x)       (sizeof(x) / sizeof((x)[0]) )

void md_install_service() {
	char szPath[512];

	GetModuleFileName(NULL, szPath, COUNTOF(szPath));

	SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

	SC_HANDLE hService = CreateService(
		hSCManager,
		SVCNAME,            /* name of service */
		"Simple Lldp Agent service",  /* name to display */
		SERVICE_ALL_ACCESS,           /* desired access */
		SERVICE_WIN32_OWN_PROCESS,    /* service type */
		SERVICE_AUTO_START,           /* start type */
		SERVICE_ERROR_NORMAL,         /* error control type */
		szPath,                       /* service's binary */
		NULL,                         /* no load order grp */
		NULL,                         /* no tag identifier */
		"",                           /* dependencies */
		0,                            /* LocalSystem account */
		0);                           /* no password */

// Try start service
	StartService(hService, 0, 0);

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
}

void md_service_control(DWORD dwControl) {
	switch (dwControl) {
	case SERVICE_CONTROL_SHUTDOWN:
	case SERVICE_CONTROL_STOP:

		sStatus.dwCurrentState = SERVICE_STOP_PENDING;
		sStatus.dwCheckPoint = 0;
		sStatus.dwWaitHint = 2000; /* Two seconds */
		sStatus.dwWin32ExitCode = 0;
		interrupt();

	default:
		sStatus.dwCheckPoint = 0;
	}
	SetServiceStatus(hServiceStatus, &sStatus);
}

void md_service_main(DWORD argc, char** argv) {
	wchar_t buf[128];
	mbstowcs(buf, argv[0], strlen(argv[0]) + 1);
	LPWSTR name = buf;
	hServiceStatus = RegisterServiceCtrlHandlerW(name, (LPHANDLER_FUNCTION)md_service_control);
	if (hServiceStatus == 0) {
		return;
	}

	sStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	sStatus.dwCurrentState = SERVICE_START_PENDING;
	sStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	sStatus.dwWin32ExitCode = 0;
	sStatus.dwServiceSpecificExitCode = 0;
	sStatus.dwCheckPoint = 0;
	sStatus.dwWaitHint = 2 * 1000; /* Two seconds */
	sStatus.dwCurrentState = SERVICE_RUNNING;

	SetServiceStatus(hServiceStatus, &sStatus);

	/* The actual code the service runs */
	loop();

	/* Clean up the stopped service; otherwise we get a nasty error in Win32 */
	sStatus.dwCurrentState = SERVICE_STOPPED;
	SetServiceStatus(hServiceStatus, &sStatus);
}

void md_remove_service() {
	SERVICE_STATUS ssp;
	SC_HANDLE hService = 0;
	SC_HANDLE hSCManager = OpenSCManager(0, 0, 0);
	hService = OpenService(hSCManager, SVCNAME, DELETE | SERVICE_STOP);
	ControlService(hService, SERVICE_CONTROL_STOP, &ssp);
	DeleteService(hService);
	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
}
