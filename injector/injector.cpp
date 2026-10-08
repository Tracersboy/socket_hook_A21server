// injector.cpp
// 32-bit DLL injector. Lists running processes, lets the user pick one by
// process name (or PID) and injects A21hook.dll via CreateRemoteThread +
// LoadLibraryW. The injector and the DLL must match the target process
// bitness (this project is built as x86 / 32-bit only).
//
// Usage:
//   injector.exe                  -> interactive mode (list + prompt)
//   injector.exe -p <name|pid>    -> inject into matching process
//   injector.exe -p <name|pid> -d <full\path\hook.dll>

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <tlhelp32.h>

#include <cwctype>
#include <cstdio>
#include <string>
#include <vector>

namespace {

struct ProcInfo {
    DWORD pid;
    std::wstring name;
};

std::vector<ProcInfo> ListProcesses() {
    std::vector<ProcInfo> result;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return result;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            result.push_back({pe.th32ProcessID, pe.szExeFile});
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return result;
}

bool EnableDebugPrivilege() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;

    LUID luid;
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
        CloseHandle(token);
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    DWORD err = GetLastError();
    CloseHandle(token);
    return ok && err != ERROR_NOT_ALL_ASSIGNED;
}

bool InjectDll(DWORD pid, const std::wstring& dllPath, DWORD& lastError) {
    HANDLE proc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!proc) {
        lastError = GetLastError();
        return false;
    }

    bool ok = false;
    SIZE_T pathBytes = (dllPath.size() + 1) * sizeof(wchar_t);
    LPVOID remotePath = VirtualAllocEx(proc, nullptr, pathBytes,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remotePath) {
        if (WriteProcessMemory(proc, remotePath, dllPath.c_str(), pathBytes, nullptr)) {
            HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
            LPTHREAD_START_ROUTINE loadLibrary =
                reinterpret_cast<LPTHREAD_START_ROUTINE>(
                    GetProcAddress(kernel32, "LoadLibraryW"));
            if (loadLibrary) {
                HANDLE thread = CreateRemoteThread(proc, nullptr, 0, loadLibrary,
                                                   remotePath, 0, nullptr);
                if (thread) {
                    WaitForSingleObject(thread, 15000);
                    DWORD exitCode = 0;
                    GetExitCodeThread(thread, &exitCode);
                    // LoadLibraryW returns the DLL base address (nonzero) on success.
                    ok = (exitCode != 0);
                    if (!ok) lastError = GetLastError();
                    CloseHandle(thread);
                } else {
                    lastError = GetLastError();
                }
            } else {
                lastError = GetLastError();
            }
        } else {
            lastError = GetLastError();
        }
        VirtualFreeEx(proc, remotePath, 0, MEM_RELEASE);
    } else {
        lastError = GetLastError();
    }

    CloseHandle(proc);
    return ok;
}

std::wstring GetModuleDir() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring p(path);
    size_t pos = p.find_last_of(L"\\/");
    return pos == std::wstring::npos ? L"." : p.substr(0, pos);
}

bool IsAllDigits(const std::wstring& s) {
    if (s.empty()) return false;
    for (wchar_t c : s)
        if (!iswdigit(c)) return false;
    return true;
}

bool ContainsNoCase(const std::wstring& haystack, const std::wstring& needle) {
    if (needle.size() > haystack.size()) return false;
    for (size_t i = 0; i + needle.size() <= haystack.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < needle.size(); ++j) {
            if (towlower(haystack[i + j]) != towlower(needle[j])) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

void PrintUsage(const wchar_t* argv0) {
    wprintf(L"用法:\n");
    wprintf(L"  %s                      交互模式:列出进程,按名称或 PID 选择\n", argv0);
    wprintf(L"  %s -p <进程名|PID>      注入指定进程\n", argv0);
    wprintf(L"  %s -p <进程名|PID> -d <dll完整路径>\n", argv0);
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    std::wstring targetArg;
    std::wstring dllPath;

    for (int i = 1; i < argc; ++i) {
        std::wstring a(argv[i]);
        if (a == L"-p" && i + 1 < argc) {
            targetArg = argv[++i];
        } else if (a == L"-d" && i + 1 < argc) {
            dllPath = argv[++i];
        } else if (a == L"-h" || a == L"--help") {
            PrintUsage(argv[0]);
            return 0;
        } else {
            wprintf(L"未知参数: %s\n", a.c_str());
            PrintUsage(argv[0]);
            return 1;
        }
    }

    if (dllPath.empty()) dllPath = GetModuleDir() + L"\\A21hook.dll";

    DWORD attr = GetFileAttributesW(dllPath.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) {
        wprintf(L"[!] 找不到注入 DLL: %s\n", dllPath.c_str());
        wprintf(L"    请将 A21hook.dll 与 injector.exe 放在同一目录,或用 -d 指定路径。\n");
        return 1;
    }

    std::vector<ProcInfo> procs = ListProcesses();
    if (procs.empty()) {
        wprintf(L"[!] 无法枚举进程(权限不足?)\n");
        return 1;
    }

    DWORD pid = 0;

    if (targetArg.empty()) {
        wprintf(L"=== 进程列表 (共 %zu 个) ===\n", procs.size());
        wprintf(L"%-8s %s\n", L"PID", L"进程名");
        for (const auto& p : procs)
            wprintf(L"%-8lu %s\n", p.pid, p.name.c_str());

        wchar_t input[256];
        std::vector<ProcInfo> matches;
        while (true) {
            wprintf(L"\n输入进程名(支持部分匹配)或 PID,回车确认: ");
            if (!fgetws(input, 256, stdin)) return 1;
            std::wstring q(input);
            while (!q.empty() && (q.back() == L'\n' || q.back() == L'\r')) q.pop_back();

            if (q.empty()) continue;

            if (IsAllDigits(q)) {
                pid = static_cast<DWORD>(_wtoi(q.c_str()));
                break;
            }

            matches.clear();
            for (const auto& p : procs) {
                if (ContainsNoCase(p.name, q)) matches.push_back(p);
            }

            if (matches.empty()) {
                wprintf(L"[!] 没有匹配 \"%s\" 的进程,请重试。\n", q.c_str());
            } else if (matches.size() == 1) {
                pid = matches[0].pid;
                wprintf(L"[*] 匹配: %s (PID %lu)\n", matches[0].name.c_str(), pid);
                break;
            } else {
                wprintf(L"匹配到 %zu 个进程:\n", matches.size());
                for (size_t i = 0; i < matches.size(); ++i)
                    wprintf(L"  [%zu] %-8lu %s\n", i, matches[i].pid, matches[i].name.c_str());
                wprintf(L"输入序号或 PID: ");
                if (!fgetws(input, 256, stdin)) return 1;
                std::wstring pick(input);
                while (!pick.empty() && (pick.back() == L'\n' || pick.back() == L'\r')) pick.pop_back();
                if (IsAllDigits(pick)) {
                    size_t idx = static_cast<size_t>(_wtoi(pick.c_str()));
                    if (idx < matches.size()) {
                        pid = matches[idx].pid;
                        break;
                    }
                    // treat as raw PID
                    pid = static_cast<DWORD>(_wtoi(pick.c_str()));
                    break;
                }
            }
        }
    } else {
        if (IsAllDigits(targetArg)) {
            pid = static_cast<DWORD>(_wtoi(targetArg.c_str()));
        } else {
            for (const auto& p : procs) {
                if (ContainsNoCase(p.name, targetArg)) {
                    pid = p.pid;
                    wprintf(L"[*] 匹配: %s (PID %lu)\n", p.name.c_str(), pid);
                    break;
                }
            }
            if (!pid) {
                wprintf(L"[!] 没有匹配 \"%s\" 的进程。\n", targetArg.c_str());
                return 1;
            }
        }
    }

    if (!pid) {
        wprintf(L"[!] 无效的 PID。\n");
        return 1;
    }

    wprintf(L"[*] 请求 SeDebugPrivilege... %s\n",
            EnableDebugPrivilege() ? L"OK" : L"(失败,继续尝试)");
    wprintf(L"[*] 注入 %s -> PID %lu ...\n", dllPath.c_str(), pid);

    DWORD err = 0;
    if (InjectDll(pid, dllPath, err)) {
        wprintf(L"[+] 注入成功。目标进程内应已弹出 Hook 控制窗口。\n");
        return 0;
    }

    wprintf(L"[!] 注入失败 (PID %lu), GetLastError=%lu\n", pid, err);
    wprintf(L"    常见原因:位数不匹配(目标必须是 32 位进程)、权限不足(以管理员运行)、\n");
    wprintf(L"    或该进程受保护(反作弊/受保护进程)。\n");
    return 1;
}
