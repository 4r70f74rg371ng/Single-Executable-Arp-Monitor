// Wraper.cpp : 定義主控台應用程式的進入點。
//

#include "stdafx.h"
#include "resource.h"
#include <Windows.h>
#include <tchar.h>
#include <fstream>

#define BUFF_PATH_SIZE (MAX_PATH + 1)

inline void get_file_dir(TCHAR path[BUFF_PATH_SIZE]){
	GetCurrentDirectory(BUFF_PATH_SIZE, path);
}

inline void get_exe_name(TCHAR path[BUFF_PATH_SIZE]){
	int i,j;
	size_t len = 0;

	GetModuleFileName(
		GetModuleHandle(NULL),
		path, BUFF_PATH_SIZE);
	len = _tcslen(path);
	for (i = len-1; i >= 0; i--){
		if (path[i] == _T('\\') || path[i] == _T('/')){
			break;
		}
	}
	if (i >= 0){
		for (j = 0; j < (len-i-1); j++){
			path[j] = path[i + j+1];
		}
		path[j] = 0;
	}
}

inline void get_exe_directory(TCHAR path[BUFF_PATH_SIZE]){
	int i, j;
	size_t len = 0;

	GetModuleFileName(
		GetModuleHandle(NULL),
		path, BUFF_PATH_SIZE);
	len = _tcslen(path);
	for (i = len - 1; i >= 0; i--){
		if (path[i] == _T('\\') || path[i] == _T('/')){
			break;
		}
	}
	if (i >= 0){
		path[i] = 0;
	}
	else{
		path[0] = _T('.');
		path[1] = 0;
	}
}

bool extract_resource(DWORD RESOURCE_ID, TCHAR* filename){
	HMODULE hModule = GetModuleHandle(NULL); // get the handle to the current module (the executable file)
	HRSRC hResource = FindResource(hModule, MAKEINTRESOURCE(RESOURCE_ID), RT_RCDATA); // substitute RESOURCE_ID and RESOURCE_TYPE.
	if (!hResource)
		return false;
	HGLOBAL hMemory = LoadResource(hModule, hResource);
	DWORD dwSize = SizeofResource(hModule, hResource);
	LPVOID lpAddress = LockResource(hMemory);
	FILE* tfp = NULL;
	_tfopen_s(&tfp, filename, _T("wb"));
	std::fstream fs(tfp);
	if (!fs.is_open())
		return false;
	fs.write(reinterpret_cast<char*>(lpAddress), dwSize);
	fs.close();
	return true;
}

bool extract_binaries(){
	bool bret = true;

	bret &= extract_resource(BIN_EXE, _T("Example_Project.exe"));
	bret &= extract_resource(BIN_NPF_SYS, _T("npf.sys"));
	bret &= extract_resource(BIN_WPCAP_DLL, _T("wpcap.dll"));
	bret &= extract_resource(BIN_PACKET_DLL, _T("packet.dll"));

	return bret;
}

bool LoadDriver(TCHAR *DriverName, TCHAR *drivePath)
{
	DWORD error = NULL;
	SC_HANDLE SCManager;
	SC_HANDLE Service;

	// Establishes a connection to the service control manager on the specified computer.
	// Opens the specified service control manager database.
	SCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	_tprintf(_T("[o] Loading service: %s at %s\n") , DriverName, drivePath);

	// Creates a service object.
	// Adds the object to the specified service control manager database.
	Service = CreateService(SCManager, DriverName, DriverName,
		SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
		drivePath, NULL, NULL, NULL, NULL, NULL);
	error = GetLastError();
	if (error == 1073)
	{
		_tprintf(_T("[-] Service already exists with that name\n"));
		CloseServiceHandle(Service);
		CloseServiceHandle(SCManager);
		return NULL;
	}
	if (error > 0)
	{
		_tprintf(_T("[-] Error: %d\n"), error);
		CloseServiceHandle(SCManager);
		CloseServiceHandle(Service);
		return NULL;
	}
	if (!Service)
	{
		if (error == ERROR_SERVICE_EXISTS)
		{
			_tprintf(_T("[-] Service exists with that name already.\n"));
			CloseServiceHandle(SCManager);
			CloseServiceHandle(Service);
			return NULL;
		}
		else
		{
			CloseServiceHandle(SCManager);
			CloseServiceHandle(Service);
			_tprintf(_T("[-] Error: %d\n"), error);
			return NULL;
		}
	}

	CloseServiceHandle(SCManager);
	CloseServiceHandle(Service);
	return NULL;
}

bool StartDriver(TCHAR *DriverName)
{
	SC_HANDLE SCManager;
	SC_HANDLE Service;
	DWORD error = NULL;

	// Establishes a connection to the service control manager on the specified computer.
	// Opens the specified service control manager database.
	SCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	// Opens an existing service
	// Grabs handle to driver
	Service = OpenService(SCManager, DriverName, SERVICE_ALL_ACCESS);
	error = GetLastError();
	if (error == 1060)
	{
		_tprintf(_T("[-] No service found by name\n"));
		CloseServiceHandle(SCManager);
		CloseServiceHandle(Service);
		return NULL;
	}
	if (error > 0)
	{
		_tprintf(_T("[-] Error: %d\n"), error);
		CloseServiceHandle(SCManager);
		CloseServiceHandle(Service);
		return NULL;
	}


	StartService(Service, 0, NULL);
	error = GetLastError();
	if (error > 0)
	{
		_tprintf(_T("[-] Error: %d\n"), error);
		CloseServiceHandle(SCManager);
		CloseServiceHandle(Service);
		return NULL;
	}
	if (error == ERROR_SERVICE_ALREADY_RUNNING)
	{
		_tprintf(_T("[!] Service already running\n"));
		CloseServiceHandle(SCManager);
		CloseServiceHandle(Service);
		return NULL;
	}

	CloseServiceHandle(SCManager);
	CloseServiceHandle(Service);
	return NULL;
}

bool StopDriver(TCHAR *DriverName)
{
	SC_HANDLE SCManager;
	SC_HANDLE Service;
	SERVICE_STATUS proc;
	DWORD error = NULL;
	//ZeroMemory(proc, sizeof(SERVICE_STATUS_PROCESS));

	// Establishes a connection to the service control manager on the specified computer.
	// Opens the specified service control manager database.
	SCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	// Opens an existing service
	// Grabs handle to driver
	Service = OpenService(SCManager, DriverName, SERVICE_ALL_ACCESS);
	error = GetLastError();
	if (error == 1060)
	{
		_tprintf(_T("[-] No service found by name\n"));
		CloseServiceHandle(SCManager);
		CloseServiceHandle(Service);
		return TRUE;
	}
	if (error > 0)
	{
		_tprintf(_T("[-] Error: %d\n"), error);
		CloseServiceHandle(SCManager);
		CloseServiceHandle(Service);
		return NULL;
	}

	// Sends a control code to a service
	ControlService(Service, SERVICE_CONTROL_STOP, &proc);
	error = GetLastError();
	if (error > 0)
	{
		_tprintf(_T("[-] Error: %d\n"), error);
		CloseServiceHandle(SCManager);
		CloseServiceHandle(Service);
		return NULL;
	}

	CloseServiceHandle(SCManager);
	CloseServiceHandle(Service);
	return FALSE;
}

bool unLoadDriver(TCHAR *DriverName)
{
	SC_HANDLE SCManager;
	SC_HANDLE Service;
	DWORD error = NULL;

	bool status = StopDriver(DriverName);
	if (status == TRUE)
	{
		return NULL;
	}

	// Establishes a connection to the service control manager on the specified computer.
	// Opens the specified service control manager database.
	SCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	// Opens an existing service
	// Grabs handle to driver
	Service = OpenService(SCManager, DriverName, DELETE);
	error = GetLastError();
	if (error > 0)
	{
		_tprintf(_T("[-] Error: %d\n"), error);
		CloseServiceHandle(SCManager);
		CloseServiceHandle(Service);
		return NULL;
	}

	DeleteService(Service);
	error = GetLastError();
	if (error > 0)
	{
		_tprintf(_T("[-] Error: %d\n"), error);
		CloseServiceHandle(SCManager);
		CloseServiceHandle(Service);
		return NULL;
	}

	CloseServiceHandle(SCManager);
	CloseServiceHandle(Service);
	return NULL;
}

void get_full_working_path(TCHAR full_path[BUFF_PATH_SIZE], TCHAR filename [BUFF_PATH_SIZE]){
	size_t len = 0;
	//get_file_dir
	get_file_dir(full_path);
	len = _tcslen(full_path);
	full_path[len] = _T('\\');
	_tcscpy_s(&full_path[len + 1], BUFF_PATH_SIZE, filename);
}

void get_full_file_path(TCHAR full_path[BUFF_PATH_SIZE], TCHAR filename[BUFF_PATH_SIZE]){
	size_t len = 0;
	//get_file_dir
	get_exe_directory(full_path);
	len = _tcslen(full_path);
	full_path[len] = _T('\\');
	_tcscpy_s(&full_path[len + 1], BUFF_PATH_SIZE, filename);
}

int _tmain(int argc, _TCHAR* argv[])
{
	/*if (extract_binaries()){
		LoadDriver(_T("NPF"), _T("npf.sys"));
		StartDriver(_T("NPF"));
		WinExec("Example_Project.exe", SW_SHOW);
	}*/

	/*TCHAR path[BUFF_PATH_SIZE] = _T("");
	get_exe_directory(path);
	_tprintf(_T("location: %s\n"),path);
	get_file_dir(path);
	_tprintf(_T("location: %s\n"), path);
	get_exe_name(path);
	_tprintf(_T("name: %s\n"), path);*/


	/*TCHAR dir[BUFF_PATH_SIZE] = _T("");
	size_t len = 0;
	get_file_dir(dir);
	len = _tcslen(dir);
	dir[len] = _T('\\');
	get_exe_name(&dir[len+1]);
	_tprintf(_T("full path: %s\n"), dir);*/


	/*TCHAR dir[BUFF_PATH_SIZE] = _T("");
	get_full_working_path(dir, _T("test.sys"));
	_tprintf(_T("location: %s\n"), dir);*/

	TCHAR dir[BUFF_PATH_SIZE] = _T("");
	get_full_working_path(dir, _T("npf.sys"));

	if (extract_binaries()){
		StopDriver(_T("NPF"));
		unLoadDriver(_T("NPF"));
		LoadDriver(_T("NPF"), dir);
		StartDriver(_T("NPF"));
		WinExec("Example_Project.exe", SW_SHOW);
	}

	//system("pause");
	return 0;
}

