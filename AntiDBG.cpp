#include "AntiDBG.h"
#include <iostream>
#define SHOW_DEBUG_MESSAGES

void DBG_MSG(WORD dbg_code, const char* message)
{
#ifdef SHOW_DEBUG_MESSAGES
    printf("[DBG]: %s\n", dbg_code, message);
#endif
}

void adbg_BeingDebuggedPEB(void)
{
    BOOL found = FALSE;

#ifdef _WIN64
    found = adbg_BeingDebuggedPEBx64();
#else
    _asm
    {
        xor eax, eax;
        mov eax, fs: [0x30] ;
        mov eax, [eax + 0x02];
        and eax, 0xFF;
        mov found, eax;
    }
#endif

    if (found)
    {
        DBG_MSG(DBG_BEINGEBUGGEDPEB, "Caught by BeingDebugged PEB check!");
        exit(DBG_BEINGEBUGGEDPEB);
    }
}

void adbg_CheckRemoteDebuggerPresent(void)
{
    HANDLE hProcess = INVALID_HANDLE_VALUE;
    BOOL found = FALSE;

    hProcess = GetCurrentProcess();
    CheckRemoteDebuggerPresent(hProcess, &found);

    if (found)
    {
        DBG_MSG(DBG_CHECKREMOTEDEBUGGERPRESENT, "Caught by CheckRemoteDebuggerPresent!");
        exit(DBG_CHECKREMOTEDEBUGGERPRESENT);
    }
}

void adbg_CheckWindowName(void)
{
    BOOL found = FALSE;
    HANDLE hWindow = NULL;
    const wchar_t* WindowNameOlly = L"OllyDbg - [CPU]";
    const wchar_t* WindowNameImmunity = L"Immunity Debugger - [CPU]";

    hWindow = FindWindowW(NULL, WindowNameOlly);
    if (hWindow)
    {
        found = TRUE;
    }

    hWindow = FindWindowW(NULL, WindowNameImmunity);
    if (hWindow)
    {
        found = TRUE;
    }

    if (found)
    {
        exit(DBG_FINDWINDOW);
    }
}

void adbg_ProcessFileName(void)
{
    const wchar_t *debuggersFilename[6] = 
    {
        L"cheatengine-x86_64.exe", 
        L"ollydbg.exe", 
        L"ida.exe", 
        L"ida64.exe", 
        L"radare2.exe", 
        L"x64dbg.exe"
    };

    wchar_t* processName;
    PROCESSENTRY32W processInformation{ sizeof(PROCESSENTRY32W) };
    HANDLE processList;

    processList = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    processInformation = { sizeof(PROCESSENTRY32W) };
    if (!(Process32FirstW(processList, &processInformation)))
        printf("[Warning] It is impossible to check process list.");
    else
    {
        do
        {
            for (const wchar_t *debugger : debuggersFilename)
            {
                processName = processInformation.szExeFile;
                if (_wcsicmp(debugger, processName) == 0) {
                    DBG_MSG(DBG_PROCESSFILENAME, "Caught by ProcessFileName!");
                    exit(DBG_PROCESSFILENAME);
                }
            }
        } while (Process32NextW(processList, &processInformation));
    }
    CloseHandle(processList);
}

void adbg_CheckWindowClassName(void)
{
    BOOL found = FALSE;
    HANDLE hWindow = NULL;
    const wchar_t* WindowClassNameOlly = L"OLLYDBG";
    const wchar_t* WindowClassNameImmunity = L"ID";

    hWindow = FindWindowW(WindowClassNameOlly, NULL);
    if (hWindow)
    {
        found = TRUE;
    }

    hWindow = FindWindowW(WindowClassNameImmunity, NULL);
    if (hWindow)
    {
        found = TRUE;
    }

    if (found)
    {
        exit(DBG_FINDWINDOW);
    }
}

void adbg_IsDebuggerPresent(void)
{
    BOOL found = FALSE;
    found = IsDebuggerPresent();

    if (found)
    {
        exit(DBG_ISDEBUGGERPRESENT);
    }
}

void adbg_NtGlobalFlagPEB(void)
{
    BOOL found = FALSE;

#ifdef _WIN64
    found = adbg_NtGlobalFlagPEBx64();
#else
    _asm
    {
        xor eax, eax;
        mov eax, fs: [0x30] ;
        mov eax, [eax + 0x68];
        and eax, 0x00000070;
                        
        mov found, eax;		
    }
#endif

    if (found)
    {
        DBG_MSG(DBG_NTGLOBALFLAGPEB, "Caught by NtGlobalFlag PEB check!");
        exit(DBG_NTGLOBALFLAGPEB);
    }
}


void adbg_NtQueryInformationProcess(void)
{
    HANDLE hProcess = INVALID_HANDLE_VALUE;
    PROCESS_BASIC_INFORMATION pProcBasicInfo = {0};
    ULONG returnLength = 0;
    HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
    if (hNtdll == INVALID_HANDLE_VALUE || hNtdll == NULL)
    {
        return;
    }

    _NtQueryInformationProcess  NtQueryInformationProcess = NULL;
    NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

    if (NtQueryInformationProcess == NULL)
    {
        return;
    }
    
    hProcess = GetCurrentProcess();
    
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pProcBasicInfo, sizeof(pProcBasicInfo), &returnLength);
    if (NT_SUCCESS(status)) {
        PPEB pPeb = pProcBasicInfo.PebBaseAddress;
        if (pPeb)
        {
            if (pPeb->BeingDebugged)
            {
                DBG_MSG(DBG_NTQUERYINFORMATIONPROCESS, "Caught by NtQueryInformationProcess (ProcessDebugPort)!");
                exit(DBG_NTQUERYINFORMATIONPROCESS);
            }
        }
    }
}


void adbg_NtSetInformationThread(void)
{
    THREAD_INFORMATION_CLASS ThreadHideFromDebugger = (THREAD_INFORMATION_CLASS)0x11;

    HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
    if (hNtdll == INVALID_HANDLE_VALUE || hNtdll == NULL)
    {
        return;
    }

    _NtSetInformationThread NtSetInformationThread = NULL;
    NtSetInformationThread = (_NtSetInformationThread)GetProcAddress(hNtdll, "NtSetInformationThread");

    if (NtSetInformationThread == NULL)
    {
        return;
    }

    NtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, 0, 0);
}


void adbg_DebugActiveProcess(const char* cpid)
{
    BOOL found = FALSE;
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);
    TCHAR szPath[MAX_PATH];
    DWORD exitCode = 0;

    CreateMutexW(NULL, FALSE, L"antidbg");
    if (GetLastError() != ERROR_SUCCESS)
    {
        if (DebugActiveProcess((DWORD)atoi(cpid)))
        {
            return;
        }
        else
        {
            exit(555);
        }
    }

    DWORD pid = GetCurrentProcessId();
    GetModuleFileName(NULL, szPath, MAX_PATH);

    char cmdline[MAX_PATH + 1 + sizeof(int)];
    snprintf(cmdline, sizeof(cmdline), "%ws %d", szPath, pid);

    BOOL success = CreateProcessA(
        NULL,
        cmdline,
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        &si,
        &pi);

    WaitForSingleObject(pi.hProcess, INFINITE);

    GetExitCodeProcess(pi.hProcess, &exitCode);
    if (exitCode == 555)
    {
        found = TRUE;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (found)
    {
        DBG_MSG(DBG_DEBUGACTIVEPROCESS, "Caught by DebugActiveProcess!");
        exit(DBG_DEBUGACTIVEPROCESS);
    }
}

void adbg_RDTSC(void)
{
    BOOL found = FALSE;

#ifdef _WIN64
    uint64_t timeA = 0;
    uint64_t timeB = 0;
    TimeKeeper timeKeeper = { 0 };
    adbg_RDTSCx64(&timeKeeper);
    
    timeA = timeKeeper.timeUpperA;
    timeA = (timeA << 32) | timeKeeper.timeLowerA;

    timeB = timeKeeper.timeUpperB;
    timeB = (timeB << 32) | timeKeeper.timeLowerB;

    if (timeB - timeA > 0x100000)
    {
        found = TRUE;
    }

#else
    int timeUpperA = 0;
    int timeLowerA = 0;
    int timeUpperB = 0;
    int timeLowerB = 0;
    int timeA = 0;
    int timeB = 0;

    _asm
    {
        rdtsc;
        mov [timeUpperA], edx;
        mov [timeLowerA], eax;

        xor eax, eax;
        mov eax, 5;
        shr eax, 2;
        sub eax, ebx;
        cmp eax, ecx;

        rdtsc;
        mov [timeUpperB], edx;
        mov [timeLowerB], eax;
    }

    timeA = timeUpperA;
    timeA = (timeA << 32) | timeLowerA;

    timeB = timeUpperB;
    timeB = (timeB << 32) | timeLowerB;

    if (timeB - timeA > 0x10000)
    {
        found = TRUE;
    }

#endif

    if (found)
    {
        DBG_MSG(DBG_RDTSC, "Caught by RDTSC!");
        exit(DBG_RDTSC);
    }
}


void adbg_QueryPerformanceCounter(void)
{
    BOOL found = FALSE;
    LARGE_INTEGER t1;
    LARGE_INTEGER t2;

    QueryPerformanceCounter(&t1);

#ifdef _WIN64
    adbg_QueryPerformanceCounterx64();
#else
    _asm
    {
        xor eax, eax;
        push eax;
        push ecx;
        pop eax;
        pop ecx;
        sub ecx, eax;
        shl ecx, 4;
    }
#endif

    QueryPerformanceCounter(&t2);

    if ((t2.QuadPart - t1.QuadPart) > 30)
    {
        found = TRUE;
    }

    if (found)
    {
        DBG_MSG(DBG_QUERYPERFORMANCECOUNTER, "Caught by QueryPerformanceCounter!");
        exit(DBG_QUERYPERFORMANCECOUNTER);
    }
}


void adbg_GetTickCount(void)
{
    BOOL found = FALSE;
    DWORD t1;
    DWORD t2;

    t1 = GetTickCount();

#ifdef _WIN64
    adbg_GetTickCountx64();
#else
    _asm
    {
        xor eax, eax;
        push eax;
        push ecx;
        pop eax;
        pop ecx;
        sub ecx, eax;
        shl ecx, 4;
    }
#endif

    t2 = GetTickCount();
    if ((t2 - t1) > 30)
    {
        found = TRUE;
    }

    if (found)
    {
        DBG_MSG(DBG_GETTICKCOUNT, "Caught by GetTickCount!");
        exit(DBG_GETTICKCOUNT);
    }
}

void adbg_HardwareDebugRegisters(void)
{
    BOOL found = FALSE;
    CONTEXT ctx = { 0 };
    HANDLE hThread = GetCurrentThread();

    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(hThread, &ctx))
    {
        if ((ctx.Dr0 != 0x00) || (ctx.Dr1 != 0x00) || (ctx.Dr2 != 0x00) || (ctx.Dr3 != 0x00) || (ctx.Dr6 != 0x00) || (ctx.Dr7 != 0x00))
        {
            found = TRUE;
        }
    }

    if (found)
    {
        DBG_MSG(DBG_HARDWAREDEBUGREGISTERS, "Caught by a Hardware Debug Register Check!");
        exit(DBG_HARDWAREDEBUGREGISTERS);
    }
}


void adbg_MovSS(void)
{
    BOOL found = FALSE;

#ifdef _WIN64
#else
    _asm
    {
        push ss;
        pop ss;
        pushfd;
        test byte ptr[esp + 1], 1;
        jne fnd;
        jmp end;
    fnd:
        mov found, 1;
    end:
        nop;
    }
#endif

    if (found)
    {
        DBG_MSG(DBG_MOVSS, "Caught by a MOV SS Single Step Check!");
        exit(DBG_MOVSS);
    }
}

void adbg_CloseHandleException(void)
{
    HANDLE hInvalid = (HANDLE)0xBEEF;
    DWORD found = FALSE;

    __try
    {
        CloseHandle(hInvalid);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        found = TRUE;
    }

    if (found)
    {
        DBG_MSG(DBG_CLOSEHANDLEEXCEPTION, "Caught by an CloseHandle exception!");
        exit(DBG_CLOSEHANDLEEXCEPTION);
    }
}


void adbg_SingleStepException(void)
{
    DWORD found = TRUE;
    __try
    {
#ifdef _WIN64
        adbg_SingleStepExceptionx64();
#else
        _asm
        {
            pushfd;					
            or byte ptr[esp + 1], 1;	
            popfd;						
        }
#endif
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        found = FALSE;
    }

    if (found)
    {
        DBG_MSG(DBG_SINGLESTEPEXCEPTION, "Caught by a Single Step Exception!");
        exit(DBG_SINGLESTEPEXCEPTION);
    }
}


void adbg_Int3(void)
{
    BOOL found = TRUE;

    __try
    {
#ifdef _WIN64
        adbg_Int3x64();
#else
        _asm
        {
            int 3;
        }
#endif
    }

    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        found = FALSE;
    }

    if (found)
    {
        DBG_MSG(DBG_INT3CC, "Caught by a rogue INT 3!");
        exit(DBG_INT3CC);
    }
}


void adbg_PrefixHop(void)
{
    BOOL found = TRUE;

    __try
    {
#ifdef _WIN64
        found = FALSE;
#else
        _asm
        {
            __emit 0xF3;
            __emit 0x64;
            __emit 0xCC;
        }
#endif
    }

    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        found = FALSE;
    }

    if (found)
    {
        DBG_MSG(DBG_PREFIXHOP, "Caught by a Prefix Hop!");
        exit(DBG_PREFIXHOP);
    }
}


void adbg_Int2D(void)
{
    BOOL found = TRUE;

    __try
    {
#ifdef _WIN64
        adbg_Int2Dx64();
#else
        _asm
        {
            int 0x2D;
            nop;
        }
#endif
    }

    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        found = FALSE;
    }

    if (found)
    {
        DBG_MSG(DBG_NONE, "Caught by a rogue INT 2D!");
        exit(DBG_NONE);
    }
}

void adbg_CrashOllyDbg(void)
{
    __try {
        OutputDebugString(TEXT("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s"));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { ; }
}
