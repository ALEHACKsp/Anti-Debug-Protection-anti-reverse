#include <iostream>
#include <string>
#include <fstream>
#include <thread>
#include <vector>
#include <random>
#include <filesystem>
#include <Windows.h>
#include <TlHelp32.h>
#include <stdint.h>

#include "AntiDBG.h"
#include "encryptXOR.hpp"

#define _CRT_SECURE_NO_WARNINGS
#define SELF_REMOVE_STRING TEXT("cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q \"%s\"")

inline bool file_exists(const std::string& name)
{
	struct stat buffer;
	return (stat(name.c_str(), &buffer) == 0);
}

extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN OldValue);
extern "C" NTSTATUS NTAPI NtRaiseHardError(LONG ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask, PULONG_PTR Parameters, ULONG ValidResponseOptions, PULONG Response);

NTSTATUS RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN OldValue)
{
	return NTSTATUS();
}

NTSTATUS NtRaiseHardError(LONG ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask, PULONG_PTR Parameters, ULONG ValidResponseOptions, PULONG Response)
{
	return NTSTATUS();
}

typedef NTSTATUS(NTAPI* pdef_NtRaiseHardError)(NTSTATUS ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask OPTIONAL, PULONG_PTR Parameters, ULONG ResponseOption, PULONG Response);
typedef NTSTATUS(NTAPI* pdef_RtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);

void bsod()
{
	BOOLEAN bEnabled;
	ULONG uResp;
	system(XorString("cls"));
	std::ofstream outfile(XorString("C:\\Windows\\System32\\kdtt64.txt"));
	outfile << XorString("0xB02F01\n0xB868R0\n0x1ABEB1") << std::endl;
	outfile.close();
	LPVOID lpFuncAddress = GetProcAddress(LoadLibraryA(XorString("ntdll.dll")), XorString("RtlAdjustPrivilege"));
	LPVOID lpFuncAddress2 = GetProcAddress(GetModuleHandleW(XorWideString(L"ntdll.dll")), XorString("NtRaiseHardError"));
	pdef_RtlAdjustPrivilege NtCall = (pdef_RtlAdjustPrivilege)lpFuncAddress;
	pdef_NtRaiseHardError NtCall2 = (pdef_NtRaiseHardError)lpFuncAddress2;
	NTSTATUS NtRet = NtCall(19, TRUE, FALSE, &bEnabled);
	NtCall2(STATUS_FLOAT_MULTIPLE_FAULTS, 0, 0, 0, 6, &uResp);
}


static std::string RandomProcess()
{
	std::vector<std::string> Process
	{
		XorString("Taskmgr.exe"),
		XorString("regedit.exe"),
		XorString("notepad.exe"),
		XorString("mspaint.exe"),
		XorString("winver.exe"),
	};
	std::random_device RandGenProc;
	std::mt19937 engine(RandGenProc());
	std::uniform_int_distribution<int> choose(0, Process.size() - 1);
	std::string RandProc = Process[choose(engine)];
	return RandProc;
}

std::wstring s2ws(const std::string& s)
{
	std::string curLocale = setlocale(LC_ALL, XorString(""));
	const char* _Source = s.c_str();
	size_t _Dsize = mbstowcs(NULL, _Source, 0) + 1;
	wchar_t* _Dest = new wchar_t[_Dsize];
	wmemset(_Dest, 0, _Dsize);
	mbstowcs(_Dest, _Source, _Dsize);
	std::wstring result = _Dest;
	delete[]_Dest;
	setlocale(LC_ALL, curLocale.c_str());
	return result;
}

const wchar_t* ProcessBlacklist[] =
{
	XorWideString(L"WinDbgFrameClass"),
	XorWideString(L"OLLYDBG"),
	XorWideString(L"IDA"),
	XorWideString(L"IDA64"),
	XorWideString(L"ida64.exe"),
	XorWideString(L"ida.exe"),
	XorWideString(L"idaq64.exe"),
	XorWideString(L"KsDumper"),
	XorWideString(L"x64dbg"),
	XorWideString(L"The Wireshark Network Analyzer"),
	XorWideString(L"Progress Telerik Fiddler Web Debugger"),
	XorWideString(L"dnSpy"),
	XorWideString(L"IDA v7.0.170914"),
	XorWideString(L"ImmunityDebugger")
};

const wchar_t* FileBlacklist[] =
{
	XorWideString(L"CEHYPERSCANSETTINGS"),
};

typedef NTSTATUS(CALLBACK* NtSetInformationThreadPtr)(HANDLE threadHandle, THREADINFOCLASS threadInformationClass, PVOID threadInformation, ULONG threadInformationLength);

void StopDebegger()
{
	HMODULE hModule = LoadLibrary(TEXT("ntdll.dll"));
	NtSetInformationThreadPtr NtSetInformationThread = (NtSetInformationThreadPtr)GetProcAddress(hModule, XorString("NtSetInformationThread"));

	NtSetInformationThread(OpenThread(THREAD_ALL_ACCESS, FALSE, GetCurrentThreadId()), (THREADINFOCLASS)0x11, 0, 0);
}

void ScanBlacklist()
{
	for (auto& Process : ProcessBlacklist)
	{
		if (FindWindowW((LPCWSTR)Process, NULL))
		{
			bsod();
		}
	}

	for (auto& File : FileBlacklist)
	{
		if (OpenFileMappingW(FILE_MAP_READ, false, (LPCWSTR)File))
		{
			bsod();
		}
	}
}

void DebuggerPresent()
{
	if (IsDebuggerPresent())
	{
		bsod();
	}
}

DWORD_PTR FindProcessId2(const std::string& processName)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	Process32First(processesSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processesSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processesSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	CloseHandle(processesSnapshot);
	return 0;
}

void ScanBlacklistedWindows()
{
	if (FindProcessId2(XorString("ollydbg.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("ProcessHacker.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("Dump-Fixer.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("kdstinker.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("tcpview.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("autoruns.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("autorunsc.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("filemon.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("procmon.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("regmon.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("procexp.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("ImmunityDebugger.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("Wireshark.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("dumpcap.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("HookExplorer.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("ImportREC.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("PETools.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("LordPE.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("dumpcap.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("SysInspector.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("proc_analyzer.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("sysAnalyzer.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("sniff_hit.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("windbg.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("joeboxcontrol.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("Fiddler.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("joeboxserver.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("ida64.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("ida.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("idaq64.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("Vmtoolsd.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("Vmwaretrat.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("Vmwareuser.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("Vmacthlp.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("vboxservice.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("vboxtray.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("ReClass.NET.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("x64dbg.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("OLLYDBG.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("Cheat Engine.exe")) != 0)
	{
		bsod();
	}
	else if (FindWindow(NULL, XorString("The Wireshark Network Analyzer")))
	{
		bsod();
	}
	else if (FindWindow(NULL, XorString("Progress Telerik Fiddler Web Debugger")))
	{
		bsod();
	}
	else if (FindWindow(NULL, XorString("x64dbg")))
	{
		bsod();
	}
	else if (FindWindow(NULL, XorString("KsDumper")))
	{
		bsod();
	}
	else if (FindProcessId2(XorString("KsDumper.exe")) != 0)
	{
		bsod();
	}
	else if (FindWindow(NULL, XorString("dnSpy")))
	{
		bsod();
	}
	else if (FindProcessId2(XorString("dnSpy.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("cheatengine-i386.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("cheatengine-x86_64.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("Fiddler Everywhere.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("HTTPDebuggerSvc.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId2(XorString("Fiddler.WebUi.exe")) != 0)
	{
		bsod();
	}
	else if (FindWindow(NULL, XorString("idaq64")))
	{
		bsod();
	}
	else if (FindWindow(NULL, XorString("Fiddler Everywhere")))
	{
		bsod();
	}
	else if (FindWindow(NULL, XorString("Wireshark")))
	{
		bsod();
	}
	else if (FindWindow(NULL, XorString("Dumpcap")))
	{
		bsod();
	}
	else if (FindWindow(NULL, XorString("Fiddler.WebUi")))
	{
		bsod();
	}
	else if (FindWindow(NULL, XorString("HTTP Debugger (32bits)")))
	{
		bsod();
	}
	else if (FindWindow(NULL, XorString("HTTP Debugger")))
	{
		bsod();
	}
	else if (FindWindow(NULL, XorString("ida64")))
	{
		bsod();
	}
	else if (FindWindow(NULL, XorString("IDA v7.0.170914")))
	{
		bsod();
	}
	else if (FindProcessId2(XorString("createdump.exe")) != 0)
	{
		bsod();
	}
}
void driverdetect()
{
	const TCHAR* devices[] =
	{
		(XorString("\\\\.\\kdstinker")),
		(XorString("\\\\.\\NiGgEr")),
		(XorString("\\\\.\\KsDumper"))
	};

	WORD iLength = sizeof(devices) / sizeof(devices[0]);
	for (int i = 0; i < iLength; i++)
	{
		HANDLE hFile = CreateFile(devices[i], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		TCHAR msg[256] = "";
		if (hFile != INVALID_HANDLE_VALUE)
		{
			system(XorString("start cmd /c START CMD /C \"COLOR C && TITLE Protection && ECHO KsDumper Detected. && TIMEOUT 10 >nul"));
			bsod();
		}
		else
		{

		}
	}
}
void IsDebuggerPresentPatched()
{
	HMODULE hKernel32 = GetModuleHandleA(XorString("kernel32.dll"));
	if (!hKernel32) {}

	FARPROC pIsDebuggerPresent = GetProcAddress(hKernel32, XorString("IsDebuggerPresent"));
	if (!pIsDebuggerPresent) {}

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot)
	{
	}

	PROCESSENTRY32W ProcessEntry;
	ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);

	if (!Process32FirstW(hSnapshot, &ProcessEntry))
	{
	}

	bool bDebuggerPresent = false;
	HANDLE hProcess = NULL;
	DWORD dwFuncBytes = 0;
	const DWORD dwCurrentPID = GetCurrentProcessId();
	do
	{
		__try
		{
			if (dwCurrentPID == ProcessEntry.th32ProcessID)
				continue;

			hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessEntry.th32ProcessID);
			if (NULL == hProcess)
				continue;

			if (!ReadProcessMemory(hProcess, pIsDebuggerPresent, &dwFuncBytes, sizeof(DWORD), NULL))
				continue;

			if (dwFuncBytes != *(PDWORD)pIsDebuggerPresent)
			{
				bDebuggerPresent = true;
				bsod();
				break;
			}
		}
		__finally
		{
			if (hProcess)
				CloseHandle(hProcess);
			else
			{

			}
		}
	} while (Process32NextW(hSnapshot, &ProcessEntry));

	if (hSnapshot)
		CloseHandle(hSnapshot);
}
void AntiAttach()
{
	HMODULE hNtdll = GetModuleHandleA(XorString("ntdll.dll"));
	if (!hNtdll)
		return;

	FARPROC pDbgBreakPoint = GetProcAddress(hNtdll, XorString("DbgBreakPoint"));
	if (!pDbgBreakPoint)
		return;

	DWORD dwOldProtect;
	if (!VirtualProtect(pDbgBreakPoint, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		return;

	*(PBYTE)pDbgBreakPoint = (BYTE)0xC3;
}

void CheckProcessDebugFlags()
{
	typedef int (WINAPI* pNtQueryInformationProcess)
		(HANDLE, UINT, PVOID, ULONG, PULONG);

	DWORD NoDebugInherit = 0;
	int Status;

	pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandle(TEXT(XorString("ntdll.dll"))), XorString("NtQueryInformationProcess"));


	Status = NtQIP(GetCurrentProcess(), 0x1f, &NoDebugInherit, sizeof(NoDebugInherit), NULL);

	if (Status != 0x00000000) {}

	if (NoDebugInherit == FALSE)
	{
		bsod();
		::exit(0);
	}
	else {}
}

void killdbg()
{
	system(XorString("taskkill /f /im KsDumperClient.exe >nul 2>&1"));
	system(XorString("taskkill /f /im KsDumper.exe >nul 2>&1"));
	system(XorString("taskkill /f /im HTTPDebuggerUI.exe >nul 2>&1"));
	system(XorString("taskkill /f /im HTTPDebuggerSvc.exe >nul 2>&1"));
	system(XorString("taskkill /f /im ProcessHacker.exe >nul 2>&1"));
	system(XorString("taskkill /f /im idaq.exe >nul 2>&1"));
	system(XorString("taskkill /f /im idaq64.exe >nul 2>&1"));
	system(XorString("taskkill /f /im Wireshark.exe >nul 2>&1"));
	system(XorString("taskkill /f /im Fiddler.exe >nul 2>&1"));
	system(XorString("taskkill /f /im FiddlerEverywhere.exe >nul 2>&1"));
	system(XorString("taskkill /f /im Xenos64.exe >nul 2>&1"));
	system(XorString("taskkill /f /im Xenos.exe >nul 2>&1"));
	system(XorString("taskkill /f /im Xenos32.exe >nul 2>&1"));
	system(XorString("taskkill /f /im de4dot.exe >nul 2>&1"));
	system(XorString("taskkill /f /im Cheat Engine.exe >nul 2>&1"));
	system(XorString("taskkill /f /im HTTP Debugger Windows Service (32 bit).exe >nul 2>&1"));
	system(XorString("taskkill /f /im KsDumper.exe >nul 2>&1"));
	system(XorString("taskkill /f /im OllyDbg.exe >nul 2>&1"));
	system(XorString("taskkill /f /im x64dbg.exe >nul 2>&1"));
	system(XorString("taskkill /f /im x32dbg.exe >nul 2>&1"));
	system(XorString("taskkill /FI \"IMAGENAME eq httpdebugger*\" /IM * /F /T >nul 2>&1"));
	system(XorString("taskkill /f /im HTTPDebuggerUI.exe >nul 2>&1"));
	system(XorString("taskkill /f /im HTTPDebuggerSvc.exe >nul 2>&1"));
	system(XorString("taskkill /f /im Ida64.exe >nul 2>&1"));
	system(XorString("taskkill /f /im OllyDbg.exe >nul 2>&1"));
	system(XorString("taskkill /f /im Dbg64.exe >nul 2>&1"));
	system(XorString("taskkill /f /im Dbg32.exe >nul 2>&1"));
	system(XorString("taskkill /FI \"IMAGENAME eq cheatengine*\" /IM * /F /T >nul 2>&1"));
	system(XorString("taskkill /FI \"IMAGENAME eq httpdebugger*\" /IM * /F /T >nul 2>&1"));
	system(XorString("taskkill /FI \"IMAGENAME eq processhacker*\" /IM * /F /T >nul 2>&1"));
}
void selamdebugger()
{
	SetLastError(0);
	OutputDebugStringA(XorString("selam"));
	if (GetLastError() != 0)
	{
		bsod();
		Sleep(1);
		exit(1);
	}
}

void koruma0()
{
	{
		if (IsDebuggerPresent())
		{
			bsod();
			Sleep(1);
			exit(1);
		}
	}
}
void Debugkor()
{
	__try
	{
		DebugBreak();
	}
	__except (GetExceptionCode() == EXCEPTION_BREAKPOINT ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
	{
	}
}
void CheckProcessDebugPort()
{
	typedef int (WINAPI* pNtQueryInformationProcess)(HANDLE, UINT, PVOID, ULONG, PULONG);

	DWORD_PTR DebugPort = 0;
	ULONG ReturnSize = 0;
	int Status;
	pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandle(TEXT(XorString("ntdll.dll"))), XorString("NtQueryInformationProcess"));

	Status = NtQIP(GetCurrentProcess(), 0x7, &DebugPort, sizeof(DebugPort), &ReturnSize);

	if (Status != 0x00000000) {}

	if (DebugPort)
	{
		bsod();
		::exit(0);
	}

	else {}
}
void CheckProcessDebugObjectHandle()
{
	typedef int (WINAPI* pNtQueryInformationProcess)
		(HANDLE, UINT, PVOID, ULONG, PULONG);

	DWORD_PTR DebugHandle = 0;
	int Status;
	ULONG ReturnSize = 0;

	// Get NtQueryInformationProcess
	pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandle(TEXT(XorString("ntdll.dll"))), XorString("NtQueryInformationProcess"));

	Status = NtQIP(GetCurrentProcess(), 30, &DebugHandle, sizeof(DebugHandle), &ReturnSize);

	if (Status != 0x00000000)
	{
	}

	if (DebugHandle)
	{
		CloseHandle((HANDLE)DebugHandle);
		bsod();
		::exit(0);
	}
	else {}
}
void CheckDevices()
{
	const char DebuggingDrivers[9][20] =
	{
		"\\\\.\\EXTREM", "\\\\.\\ICEEXT",
		"\\\\.\\NDBGMSG.VXD", "\\\\.\\RING0",
		"\\\\.\\SIWVID", "\\\\.\\SYSER",
		"\\\\.\\TRW", "\\\\.\\SYSERBOOT",
		"\0"
	};


	for (int i = 0; DebuggingDrivers[i][0] != '\0'; i++) {
		HANDLE h = CreateFileA(DebuggingDrivers[i], 0, 0, 0, OPEN_EXISTING, 0, 0);
		if (h != INVALID_HANDLE_VALUE)
		{
			CloseHandle(h);
			bsod();
			::exit(0);
		}
		CloseHandle(h);
	}
}
bool CheckHardware()
{
	CONTEXT ctx;
	ZeroMemory(&ctx, sizeof(CONTEXT));
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!GetThreadContext(GetCurrentThread(), &ctx))
		return false;

	return ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3;
}

void Anti_Debug()
{
	Debugkor();
	CheckProcessDebugPort();
	killdbg();
	CheckProcessDebugObjectHandle();
	CheckDevices();
	CheckProcessDebugFlags();
	driverdetect();
	selamdebugger();
	CheckHardware();
	koruma0();
	ScanBlacklistedWindows();
	ScanBlacklist();
	DebuggerPresent();
	StopDebegger();
	AntiAttach();
	IsDebuggerPresentPatched();
	const std::string& getbanneded = XorString("C:\\Windows\\System32\\kdtt64.txt");
	if (file_exists(getbanneded))
	{
		Sleep(2000);
		::exit(0);
	}
}

std::thread debuger(Anti_Debug);

int main(int argc, char* argv[])
{
	Anti_Debug();
	adbg_IsDebuggerPresent();
	adbg_BeingDebuggedPEB();
	adbg_NtGlobalFlagPEB();
	adbg_CheckRemoteDebuggerPresent();
	adbg_NtQueryInformationProcess();
	adbg_CheckWindowClassName();
	adbg_CheckWindowName();
	adbg_ProcessFileName();
	adbg_NtSetInformationThread();
	adbg_DebugActiveProcess(argv[1]);
	adbg_HardwareDebugRegisters();
	adbg_MovSS();
	adbg_RDTSC();
	adbg_QueryPerformanceCounter();
	adbg_GetTickCount();
	adbg_CloseHandleException();
	adbg_SingleStepException();
	adbg_Int3();
	adbg_Int2D();
	adbg_PrefixHop();
	adbg_CrashOllyDbg();



	// Your goal is to get here in a debugger without modifying EIP yourself.
	MessageBoxA(NULL, "Congratulations! You made it!", "You Win!", 0);

	return 0;
}
