// Runs an external EXE and prints crash address + register state if it AVs.
// Usage:  seh_runner.exe <victim.exe> <arg1> [arg2...]
//
// We can't easily SEH-trap a child process; instead we use the Win32 debugger
// API: spawn the victim as a debugged process, wait for events, and on any
// EXCEPTION_DEBUG_EVENT print the EIP and faulting address.

#include <windows.h>
#include <stdio.h>
#include <string>

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        fwprintf(stderr, L"Usage: %s <victim.exe> [args...]\n", argv[0]);
        return 9;
    }

    std::wstring cmdline;
    for (int i = 1; i < argc; i++) {
        if (i > 1) cmdline += L" ";
        cmdline += L"\"";
        cmdline += argv[i];
        cmdline += L"\"";
    }

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};

    BOOL ok = CreateProcessW(NULL,
                              cmdline.data(),
                              NULL, NULL, FALSE,
                              DEBUG_ONLY_THIS_PROCESS,
                              NULL, NULL, &si, &pi);
    if (!ok) {
        fwprintf(stderr, L"CreateProcess failed: %lu\n", GetLastError());
        return 9;
    }

    int finalExit = 0;
    bool reportedException = false;

    DEBUG_EVENT ev;
    for (;;) {
        if (!WaitForDebugEvent(&ev, INFINITE)) break;

        switch (ev.dwDebugEventCode) {
            case EXCEPTION_DEBUG_EVENT: {
                const EXCEPTION_RECORD& er = ev.u.Exception.ExceptionRecord;
                bool isFirstChance = ev.u.Exception.dwFirstChance != 0;
                DWORD code = er.ExceptionCode;
                if (code == EXCEPTION_BREAKPOINT) {
                    // Initial loader BP — ignore and continue
                    ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
                    continue;
                }
                if (!reportedException || !isFirstChance) {
                    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, ev.dwThreadId);
                    CONTEXT ctx = {};
                    ctx.ContextFlags = CONTEXT_FULL;
                    GetThreadContext(hThread, &ctx);
                    CloseHandle(hThread);

                    printf("=== EXCEPTION (%s chance) ===\n", isFirstChance ? "first" : "second");
                    printf("code      = 0x%08X (%s)\n",
                           code,
                           (code == 0xC0000005) ? "ACCESS_VIOLATION" :
                           (code == 0xC000001D) ? "ILLEGAL_INSTRUCTION" :
                           (code == 0xC0000094) ? "INTEGER_DIVIDE_BY_ZERO" :
                           "unknown");
                    printf("addr      = 0x%p\n", er.ExceptionAddress);
                    if (code == 0xC0000005 && er.NumberParameters >= 2) {
                        printf("access    = %llu (%s)\n",
                               (unsigned long long)er.ExceptionInformation[0],
                               er.ExceptionInformation[0] == 0 ? "READ" :
                               er.ExceptionInformation[0] == 1 ? "WRITE" : "EXEC");
                        printf("fault_va  = 0x%016llX\n", (unsigned long long)er.ExceptionInformation[1]);
                    }
                    printf("RIP = 0x%016llX\n", (unsigned long long)ctx.Rip);
                    printf("RAX = 0x%016llX  RBX = 0x%016llX\n", (unsigned long long)ctx.Rax, (unsigned long long)ctx.Rbx);
                    printf("RCX = 0x%016llX  RDX = 0x%016llX\n", (unsigned long long)ctx.Rcx, (unsigned long long)ctx.Rdx);
                    printf("RSI = 0x%016llX  RDI = 0x%016llX\n", (unsigned long long)ctx.Rsi, (unsigned long long)ctx.Rdi);
                    printf("RSP = 0x%016llX  RBP = 0x%016llX\n", (unsigned long long)ctx.Rsp, (unsigned long long)ctx.Rbp);
                    printf("R8  = 0x%016llX  R9  = 0x%016llX\n", (unsigned long long)ctx.R8, (unsigned long long)ctx.R9);

                    // Dump bytes at RIP for context
                    HANDLE hProc = OpenProcess(PROCESS_VM_READ, FALSE, ev.dwProcessId);
                    unsigned char buf[32] = {};
                    SIZE_T n = 0;
                    ReadProcessMemory(hProc, (LPCVOID)ctx.Rip, buf, sizeof(buf), &n);
                    CloseHandle(hProc);
                    printf("bytes at RIP (%zu read): ", n);
                    for (SIZE_T i = 0; i < n; i++) printf("%02X ", buf[i]);
                    printf("\n");

                    reportedException = true;
                    finalExit = 7;
                }
                ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId,
                                   isFirstChance ? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE);
                break;
            }
            case EXIT_PROCESS_DEBUG_EVENT:
                if (finalExit == 0) finalExit = (int)ev.u.ExitProcess.dwExitCode;
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                return finalExit;
            default:
                ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
                break;
        }
    }

    return finalExit;
}
