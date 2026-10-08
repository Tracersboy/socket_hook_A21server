// injector.cpp
// 32-bit 图形化 DLL 注入器(GUI)。
//   - 进程列表(PID + 进程名),支持输入关键字实时筛选
//   - 选中进程点「注入」或双击列表项,通过 CreateRemoteThread + LoadLibraryW
//     注入 A21hook.dll
//   - 支持 DLL 路径手动修改 / 浏览选择;非管理员运行时可一键提权重启
//   - 保留命令行用法: injector.exe -p <进程名|PID> [-d <dll路径>]
//
// 注入器与 DLL 必须和目标进程位数一致(本项目为 x86 / 32 位)。

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cwctype>
#include <string>
#include <vector>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

namespace {

constexpr wchar_t kClassName[] = L"A21InjectorWindow";
constexpr int IDC_DLLPATH = 1001;
constexpr int IDC_BROWSE = 1002;
constexpr int IDC_FILTER = 1003;
constexpr int IDC_REFRESH = 1004;
constexpr int IDC_INJECT = 1005;
constexpr int IDC_ELEVATE = 1006;
constexpr int IDC_PROCLIST = 1007;
constexpr int IDC_LOG = 1008;

HINSTANCE g_hinst = nullptr;
HWND g_hwnd = nullptr;
HWND g_edDllPath = nullptr;
HWND g_edFilter = nullptr;
HWND g_lv = nullptr;
HWND g_log = nullptr;
HWND g_btnElevate = nullptr;

struct ProcInfo {
    DWORD pid;
    std::wstring name;
};

bool IsAllDigitsForFilter(const wchar_t* s) {
    if (!s || !*s) return false;
    for (const wchar_t* c = s; *c; ++c)
        if (!iswdigit(*c)) return false;
    return true;
}

std::vector<ProcInfo> g_procs;       // 全部进程(刷新时快照)
std::vector<const ProcInfo*> g_view; // 当前筛选后的可见项(与列表一一对应)

// ---------------------------------------------------------------------------
// 工具
// ---------------------------------------------------------------------------
std::wstring GetModuleDir() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring p(path);
    size_t pos = p.find_last_of(L"\\/");
    return pos == std::wstring::npos ? L"." : p.substr(0, pos);
}

std::wstring GetDefaultDllPath() { return GetModuleDir() + L"\\A21hook.dll"; }

bool FileExists(const std::wstring& p) {
    DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

bool IsElevated() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    TOKEN_ELEVATION e;
    DWORD len = 0;
    BOOL ok = GetTokenInformation(tok, TokenElevation, &e, sizeof(e), &len);
    CloseHandle(tok);
    return ok && e.TokenIsElevated != 0;
}

bool EnableDebugPrivilege() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return false;
    LUID luid;
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
        CloseHandle(tok);
        return false;
    }
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    DWORD err = GetLastError();
    CloseHandle(tok);
    return ok && err != ERROR_NOT_ALL_ASSIGNED;
}

bool ContainsNoCase(const std::wstring& haystack, const std::wstring& needle) {
    if (needle.empty()) return true;
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

// ---------------------------------------------------------------------------
// 日志
// ---------------------------------------------------------------------------
void LogLine(const wchar_t* fmt, ...) {
    if (!g_log) return;
    wchar_t buf[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf_s(buf, 1024, _TRUNCATE, fmt, ap);
    va_end(ap);

    wchar_t timebuf[64];
    SYSTEMTIME st;
    GetLocalTime(&st);
    swprintf(timebuf, L"[%02u:%02u:%02u] ", st.wHour, st.wMinute, st.wSecond);

    std::wstring line = timebuf + buf + L"\r\n";
    SendMessageW(g_log, EM_SETSEL, static_cast<WPARAM>(-1), static_cast<WPARAM>(-1));
    SendMessageW(g_log, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(line.c_str()));
}

// ---------------------------------------------------------------------------
// 进程枚举与列表
// ---------------------------------------------------------------------------
void SnapshotProcesses() {
    g_procs.clear();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            g_procs.push_back({pe.th32ProcessID, pe.szExeFile});
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    std::sort(g_procs.begin(), g_procs.end(),
              [](const ProcInfo& a, const ProcInfo& b) { return a.pid < b.pid; });
}

void RefillListView() {
    wchar_t filter[256] = {0};
    GetWindowTextW(g_edFilter, filter, 255);

    g_view.clear();
    for (const auto& p : g_procs) {
        if (filter[0] == L'\0' || ContainsNoCase(p.name, filter) ||
            (IsAllDigitsForFilter(filter) && std::to_wstring(p.pid).find(filter) != std::wstring::npos)) {
            g_view.push_back(&p);
        }
    }

    ListView_DeleteAllItems(g_lv);
    wchar_t pidBuf[16];
    for (size_t i = 0; i < g_view.size(); ++i) {
        const ProcInfo* p = g_view[i];
        swprintf(pidBuf, L"%lu", p->pid);
        LVITEMW li;
        li.mask = LVIF_TEXT | LVIF_PARAM;
        li.iItem = static_cast<int>(i);
        li.iSubItem = 0;
        li.pszText = pidBuf;
        li.lParam = static_cast<LPARAM>(p->pid);
        ListView_InsertItem(g_lv, &li);
        ListView_SetItemText(g_lv, static_cast<int>(i), 1,
                             const_cast<LPWSTR>(p->name.c_str()));
    }
    LogLine(L"进程列表已刷新,共 %zu 个进程,当前显示 %zu 个。", g_procs.size(), g_view.size());
}

// ---------------------------------------------------------------------------
// 注入
// ---------------------------------------------------------------------------
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
            LPTHREAD_START_ROUTINE loadLibrary = reinterpret_cast<LPTHREAD_START_ROUTINE>(
                GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW"));
            if (loadLibrary) {
                HANDLE thread = CreateRemoteThread(proc, nullptr, 0, loadLibrary,
                                                   remotePath, 0, nullptr);
                if (thread) {
                    WaitForSingleObject(thread, 15000);
                    DWORD exitCode = 0;
                    GetExitCodeThread(thread, &exitCode);
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

void InjectSelected() {
    int sel = ListView_GetNextItem(g_lv, -1, LVNI_SELECTED);
    if (sel < 0) {
        LogLine(L"请先在列表中选中一个进程。");
        return;
    }

    wchar_t path[MAX_PATH];
    GetWindowTextW(g_edDllPath, path, MAX_PATH);
    if (!FileExists(path)) {
        LogLine(L"[!] DLL 不存在: %s", path);
        return;
    }

    LVITEMW li;
    li.mask = LVIF_PARAM;
    li.iItem = sel;
    li.iSubItem = 0;
    ListView_GetItem(g_lv, &li);
    DWORD pid = static_cast<DWORD>(li.lParam);

    wchar_t nameBuf[MAX_PATH] = {0};
    ListView_GetItemTextW(g_lv, sel, 1, nameBuf, MAX_PATH);

    LogLine(L"注入 %s -> %s (PID %lu) ...", path, nameBuf, pid);
    DWORD err = 0;
    if (InjectDll(pid, path, err)) {
        LogLine(L"[+] 注入成功,目标进程内应已弹出 Hook 控制窗口。");
    } else {
        LogLine(L"[!] 注入失败, GetLastError=%lu。常见原因:目标不是 32 位进程、权限不足(以管理员运行)或进程受保护。", err);
    }
}

void RelaunchElevated() {
    wchar_t exe[MAX_PATH];
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    ShellExecuteW(nullptr, L"runas", exe, nullptr, nullptr, SW_SHOW);
}

// ---------------------------------------------------------------------------
// 界面
// ---------------------------------------------------------------------------
void CreateControls(HWND hwnd) {
    HFONT font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
    auto mk = [&](const wchar_t* cls, const wchar_t* text, DWORD style, int x, int y,
                  int w, int h, HMENU id, DWORD ex = 0) {
        HWND h = CreateWindowExW(ex, cls, text, style | WS_CHILD | WS_VISIBLE,
                                 x, y, w, h, hwnd, id, g_hinst, nullptr);
        SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
        return h;
    };

    mk(L"STATIC", L"DLL路径:", 0, 10, 13, 60, 18, nullptr);
    g_edDllPath = mk(L"EDIT", GetDefaultDllPath().c_str(),
                     WS_BORDER | ES_AUTOHSCROLL, 75, 10, 560, 22,
                     reinterpret_cast<HMENU>(IDC_DLLPATH));
    mk(L"BUTTON", L"浏览...", 0, 645, 9, 65, 24,
       reinterpret_cast<HMENU>(IDC_BROWSE));

    mk(L"STATIC", L"筛选:", 0, 10, 45, 40, 18, nullptr);
    g_edFilter = mk(L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL, 55, 42, 200, 22,
                    reinterpret_cast<HMENU>(IDC_FILTER));
    mk(L"BUTTON", L"刷新进程", 0, 265, 41, 90, 24,
       reinterpret_cast<HMENU>(IDC_REFRESH));
    g_btnElevate = mk(L"BUTTON", L"以管理员运行", 0, 365, 41, 110, 24,
                      reinterpret_cast<HMENU>(IDC_ELEVATE));
    mk(L"BUTTON", L"注入", 0, 640, 40, 70, 26,
       reinterpret_cast<HMENU>(IDC_INJECT));

    g_lv = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                           WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL |
                               LVS_SHOWSELALWAYS,
                           10, 74, 700, 330, hwnd,
                           reinterpret_cast<HMENU>(IDC_PROCLIST), g_hinst, nullptr);
    SendMessageW(g_lv, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    ListView_SetExtendedListViewStyle(g_lv, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

    LVCOLUMNW col;
    col.mask = LVCF_TEXT | LVCF_WIDTH;
    col.cx = 90;
    col.pszText = const_cast<LPWSTR>(L"PID");
    ListView_InsertColumn(g_lv, 0, &col);
    col.cx = 590;
    col.pszText = const_cast<LPWSTR>(L"进程名");
    ListView_InsertColumn(g_lv, 1, &col);

    g_log = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE |
                                ES_READONLY | ES_AUTOVSCROLL,
                            10, 410, 700, 62, hwnd,
                            reinterpret_cast<HMENU>(IDC_LOG), g_hinst, nullptr);
    SendMessageW(g_log, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);

    if (IsElevated()) {
        SetWindowTextW(g_btnElevate, L"已是管理员");
        EnableWindow(g_btnElevate, FALSE);
        LogLine(L"当前以管理员身份运行,SeDebugPrivilege: %s。",
                EnableDebugPrivilege() ? L"已启用" : L"启用失败(仍将继续)");
    } else {
        LogLine(L"[!] 当前不是管理员,注入部分受保护进程可能失败,建议点击「以管理员运行」。");
    }
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE:
            CreateControls(hwnd);
            SnapshotProcesses();
            RefillListView();
            return 0;

        case WM_COMMAND: {
            int id = LOWORD(wp);
            int code = HIWORD(wp);
            if (id == IDC_BROWSE && code == BN_CLICKED) {
                wchar_t file[MAX_PATH] = {0};
                OPENFILENAMEW ofn;
                ZeroMemory(&ofn, sizeof(ofn));
                ofn.lStructSize = sizeof(ofn);
                ofn.hwndOwner = hwnd;
                ofn.lpstrFilter = L"DLL 文件 (*.dll)\0*.dll\0所有文件 (*.*)\0*.*\0";
                ofn.lpstrFile = file;
                ofn.nMaxFile = MAX_PATH;
                ofn.Flags = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
                if (GetOpenFileNameW(&ofn))
                    SetWindowTextW(g_edDllPath, file);
            } else if (id == IDC_REFRESH && code == BN_CLICKED) {
                SnapshotProcesses();
                RefillListView();
            } else if (id == IDC_INJECT && code == BN_CLICKED) {
                InjectSelected();
            } else if (id == IDC_ELEVATE && code == BN_CLICKED) {
                RelaunchElevated();
            } else if (id == IDC_FILTER && code == EN_CHANGE) {
                RefillListView();
            }
            return 0;
        }

        case WM_NOTIFY: {
            LPNMHDR nm = reinterpret_cast<LPNMHDR>(lp);
            if (nm->idFrom == IDC_PROCLIST && nm->code == NM_DBLCLK)
                InjectSelected();
            return 0;
        }

        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

// ---------------------------------------------------------------------------
// 命令行模式: injector.exe -p <进程名|PID> [-d <dll路径>]
// ---------------------------------------------------------------------------
bool RunCommandLineMode() {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return false;

    std::wstring target, dllPath;
    bool hasArgs = false;
    for (int i = 1; i < argc; ++i) {
        std::wstring a(argv[i]);
        if (a == L"-p" && i + 1 < argc) {
            target = argv[++i];
            hasArgs = true;
        } else if (a == L"-d" && i + 1 < argc) {
            dllPath = argv[++i];
            hasArgs = true;
        }
    }
    LocalFree(argv);
    if (!hasArgs) return false;

    if (dllPath.empty()) dllPath = GetDefaultDllPath();
    EnableDebugPrivilege();

    DWORD pid = 0;
    if (IsAllDigitsForFilter(target.c_str())) {
        pid = static_cast<DWORD>(_wtoi(target.c_str()));
    } else {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe)) {
                do {
                    if (ContainsNoCase(pe.szExeFile, target)) {
                        pid = pe.th32ProcessID;
                        break;
                    }
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }
    }

    if (!pid) {
        MessageBoxW(nullptr, (L"没有找到匹配的进程: " + target).c_str(),
                    L"注入失败", MB_ICONERROR);
        return true;
    }

    DWORD err = 0;
    bool ok = InjectDll(pid, dllPath, err);
    MessageBoxW(nullptr,
                ok ? (L"注入成功 (PID " + std::to_wstring(pid) + L")").c_str()
                   : (L"注入失败 (PID " + std::to_wstring(pid) +
                      L"), GetLastError=" + std::to_wstring(err)).c_str(),
                ok ? L"成功" : L"失败", ok ? MB_ICONINFORMATION : MB_ICONERROR);
    return true;
}

}  // namespace

int APIENTRY wWinMain(HINSTANCE hinst, HINSTANCE, LPWSTR, int showCmd) {
    g_hinst = hinst;

    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icc);

    // 有命令行参数时走静默注入模式,不创建窗口。
    if (RunCommandLineMode()) return 0;

    WNDCLASSEXW wc;
    wc.cbSize = sizeof(wc);
    wc.style = 0;
    wc.lpfnWndProc = WndProc;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hInstance = hinst;
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszMenuName = nullptr;
    wc.lpszClassName = kClassName;
    wc.hIconSm = LoadIconW(nullptr, IDI_APPLICATION);
    if (!RegisterClassExW(&wc)) return 1;

    g_hwnd = CreateWindowExW(0, kClassName, L"A21 DLL 注入器 (x86)",
                             WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                             CW_USEDEFAULT, CW_USEDEFAULT, 736, 520,
                             nullptr, nullptr, hinst, nullptr);
    if (!g_hwnd) return 1;

    ShowWindow(g_hwnd, showCmd);
    UpdateWindow(g_hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return static_cast<int>(msg.wParam);
}
