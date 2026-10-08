// dllmain.cpp — A21hook.dll
// 注入到目标进程后:
//   1. MinHook inline hook ws2_32 的 send/WSASend/connect/WSAConnect/recv/WSARecv;
//   2. 通过 connect 建立连接时登记、send 时用 getpeername 兜底过滤,捕获所有
//      远端端口 = kTargetPort 的 TCP 连接 SOCKET 句柄(晚注入也能抓到);
//   3. 在目标进程内弹出一个控制窗口:输入 A、B(cmd/type/seq 可改),点击发送后按
//      gameproto.h 的格式组包并通过捕获到的 SOCKET 发出;收发日志实时显示。
//
// 仅用于你自己拥有或获授权的环境/服务器上的安全测试。

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
#include <winsock2.h>
#include <ws2tcpip.h>

#include <MinHook.h>

#include <algorithm>
#include <cstdint>
#include <cstdarg>
#include <cstdio>
#include <string>
#include <vector>

#include "gameproto.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "comctl32.lib")

namespace {

constexpr u_short kTargetPort = 10011;  // 目标远端端口
constexpr int kLogHexMaxBytes = 256;    // 每条日志最多 dump 的字节数

HINSTANCE g_hinst = nullptr;
CRITICAL_SECTION g_cs;
std::vector<SOCKET> g_targets;       // 已捕获的目标 SOCKET(受 g_cs 保护)
SOCKET g_lastActive = INVALID_SOCKET;  // 最近一次活跃/新建立的连接(受 g_cs 保护)

// ---------------------------------------------------------------------------
// 界面控件
// ---------------------------------------------------------------------------
HWND g_hwnd = nullptr;
HWND g_log = nullptr;
HWND g_edA = nullptr;
HWND g_edB = nullptr;

constexpr wchar_t kClassName[] = L"A21SockHookWindow";
constexpr int IDC_SEND = 1001;

// ---------------------------------------------------------------------------
// 日志(跨线程安全:SendMessage 到 UI 线程)
// ---------------------------------------------------------------------------
void LogLine(const std::wstring& msg) {
    if (!g_log) return;
    wchar_t timebuf[64];
    SYSTEMTIME st;
    GetLocalTime(&st);
    swprintf(timebuf, L"[%02u:%02u:%02u] ", st.wHour, st.wMinute, st.wSecond);
    std::wstring line = timebuf + msg + L"\r\n";
    SendMessageW(g_log, EM_SETSEL, static_cast<WPARAM>(-1), static_cast<WPARAM>(-1));
    SendMessageW(g_log, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(line.c_str()));
}

void LogFmt(const wchar_t* fmt, ...) {
    wchar_t buf[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf_s(buf, 1024, _TRUNCATE, fmt, ap);
    va_end(ap);
    LogLine(buf);
}

void LogFrame(const wchar_t* dir, const uint8_t* data, int len) {
    std::wstring hex;
    int n = (std::min)(len, kLogHexMaxBytes);
    wchar_t tmp[4];
    for (int i = 0; i < n; ++i) {
        swprintf(tmp, L"%02X ", data[i]);
        hex += tmp;
        if ((i + 1) % 16 == 0) hex += L"\r\n          ";
    }
    if (len > n) hex += L"...";
    LogFmt(L"%s %d bytes | %s", dir, len, hex.c_str());
}

// ---------------------------------------------------------------------------
// 目标 SOCKET 管理
// ---------------------------------------------------------------------------
bool IsTarget(SOCKET s) {
    EnterCriticalSection(&g_cs);
    bool found = std::find(g_targets.begin(), g_targets.end(), s) != g_targets.end();
    LeaveCriticalSection(&g_cs);
    return found;
}

void AddTarget(SOCKET s) {
    EnterCriticalSection(&g_cs);
    if (std::find(g_targets.begin(), g_targets.end(), s) == g_targets.end()) {
        g_targets.push_back(s);
        LogFmt(L"[+] 捕获目标 SOCKET=0x%IX (远端端口 %hu)", s, kTargetPort);
    }
    g_lastActive = s;  // 新建立的连接视为当前发送目标
    LeaveCriticalSection(&g_cs);
}

void SetLastActive(SOCKET s) {
    EnterCriticalSection(&g_cs);
    g_lastActive = s;
    LeaveCriticalSection(&g_cs);
}

SOCKET GetLastActive() {
    EnterCriticalSection(&g_cs);
    SOCKET s = g_lastActive;
    LeaveCriticalSection(&g_cs);
    return s;
}

void RemoveTarget(SOCKET s) {
    EnterCriticalSection(&g_cs);
    auto it = std::find(g_targets.begin(), g_targets.end(), s);
    if (it != g_targets.end()) g_targets.erase(it);
    if (g_lastActive == s) g_lastActive = INVALID_SOCKET;
    LeaveCriticalSection(&g_cs);
}

bool SockAddrIsTarget(const sockaddr* addr) {
    if (!addr) return false;
    if (addr->sa_family == AF_INET) {
        auto in = reinterpret_cast<const sockaddr_in*>(addr);
        return ntohs(in->sin_port) == kTargetPort;
    }
    if (addr->sa_family == AF_INET6) {
        auto in6 = reinterpret_cast<const sockaddr_in6*>(addr);
        return ntohs(in6->sin6_port) == kTargetPort;
    }
    return false;
}

// send 系列兜底过滤:已建立但未被 connect hook 登记的连接(晚注入场景)。
bool CheckPeerPort(SOCKET s) {
    if (IsTarget(s)) return true;

    sockaddr_storage ss;
    int len = sizeof(ss);
    if (getpeername(s, reinterpret_cast<sockaddr*>(&ss), &len) == 0 &&
        SockAddrIsTarget(reinterpret_cast<const sockaddr*>(&ss))) {
        AddTarget(s);
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// MinHook 原型与钩子
// ---------------------------------------------------------------------------
typedef int(WSAAPI* send_t)(SOCKET s, const char* buf, int len, int flags);
typedef int(WSAAPI* WSASend_t)(SOCKET s, LPWSABUF buffers, DWORD bufferCount,
                               LPDWORD numberOfBytesSent, DWORD flags,
                               LPWSAOVERLAPPED overlapped,
                               LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutine);
typedef int(WSAAPI* recv_t)(SOCKET s, char* buf, int len, int flags);
typedef int(WSAAPI* WSARecv_t)(SOCKET s, LPWSABUF buffers, DWORD bufferCount,
                               LPDWORD numberOfBytesRecvd, LPDWORD flags,
                               LPWSAOVERLAPPED overlapped,
                               LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutine);
typedef int(WSAAPI* connect_t)(SOCKET s, const sockaddr* name, int namelen);
typedef int(WSAAPI* WSAConnect_t)(SOCKET s, const sockaddr* name, int namelen,
                                  LPWSABUF callerData, LPWSABUF calleeData,
                                  LPQOS sQOS, LPQOS gQOS);

send_t Real_send = nullptr;
WSASend_t Real_WSASend = nullptr;
recv_t Real_recv = nullptr;
WSARecv_t Real_WSARecv = nullptr;
connect_t Real_connect = nullptr;
WSAConnect_t Real_WSAConnect = nullptr;

int WSAAPI Hook_send(SOCKET s, const char* buf, int len, int flags) {
    bool target = (buf && len > 0) && CheckPeerPort(s);
    int r = Real_send(s, buf, len, flags);
    if (target && r > 0) {
        SetLastActive(s);
        LogFrame(L"C->S", reinterpret_cast<const uint8_t*>(buf), r);
    }
    return r;
}

int WSAAPI Hook_WSASend(SOCKET s, LPWSABUF buffers, DWORD bufferCount,
                        LPDWORD numberOfBytesSent, DWORD flags,
                        LPWSAOVERLAPPED overlapped,
                        LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutine) {
    bool target = buffers && CheckPeerPort(s);
    int r = Real_WSASend(s, buffers, bufferCount, numberOfBytesSent, flags,
                         overlapped, completionRoutine);
    if (target && r == 0 && numberOfBytesSent && *numberOfBytesSent > 0) {
        SetLastActive(s);
        for (DWORD i = 0; i < bufferCount; ++i) {
            if (buffers[i].len == 0) continue;
            LogFrame(L"C->S(WSA)", reinterpret_cast<const uint8_t*>(buffers[i].buf),
                     static_cast<int>(buffers[i].len));
        }
    }
    return r;
}

int WSAAPI Hook_recv(SOCKET s, char* buf, int len, int flags) {
    int r = Real_recv(s, buf, len, flags);
    if (r > 0 && CheckPeerPort(s)) {
        SetLastActive(s);
        LogFrame(L"S->C", reinterpret_cast<const uint8_t*>(buf), r);
    }
    return r;
}

int WSAAPI Hook_WSARecv(SOCKET s, LPWSABUF buffers, DWORD bufferCount,
                        LPDWORD numberOfBytesRecvd, LPDWORD flags,
                        LPWSAOVERLAPPED overlapped,
                        LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutine) {
    int r = Real_WSARecv(s, buffers, bufferCount, numberOfBytesRecvd, flags,
                         overlapped, completionRoutine);
    if (r == 0 && numberOfBytesRecvd && *numberOfBytesRecvd > 0 && buffers &&
        CheckPeerPort(s)) {
        SetLastActive(s);
        for (DWORD i = 0; i < bufferCount; ++i) {
            if (buffers[i].len == 0) continue;
            LogFrame(L"S->C(WSA)", reinterpret_cast<const uint8_t*>(buffers[i].buf),
                     static_cast<int>(buffers[i].len));
        }
    }
    return r;
}

int WSAAPI Hook_connect(SOCKET s, const sockaddr* name, int namelen) {
    int r = Real_connect(s, name, namelen);
    if (r == 0 && SockAddrIsTarget(name))
        AddTarget(s);
    return r;
}

int WSAAPI Hook_WSAConnect(SOCKET s, const sockaddr* name, int namelen,
                           LPWSABUF callerData, LPWSABUF calleeData,
                           LPQOS sQOS, LPQOS gQOS) {
    int r = Real_WSAConnect(s, name, namelen, callerData, calleeData, sQOS, gQOS);
    if (r == 0 && SockAddrIsTarget(name))
        AddTarget(s);
    return r;
}

bool InstallHooks() {
    if (MH_Initialize() != MH_OK) return false;

    HMODULE ws = GetModuleHandleW(L"ws2_32.dll");
    if (!ws) ws = LoadLibraryW(L"ws2_32.dll");  // 目标可能尚未加载 ws2_32
    if (!ws) return false;

    auto addr = [ws](const char* name) -> LPVOID {
        return reinterpret_cast<LPVOID>(GetProcAddress(ws, name));
    };

    bool ok = true;
    ok &= MH_CreateHook(addr("send"), &Hook_send,
                        reinterpret_cast<LPVOID*>(&Real_send)) == MH_OK;
    ok &= MH_CreateHook(addr("WSASend"), &Hook_WSASend,
                        reinterpret_cast<LPVOID*>(&Real_WSASend)) == MH_OK;
    ok &= MH_CreateHook(addr("recv"), &Hook_recv,
                        reinterpret_cast<LPVOID*>(&Real_recv)) == MH_OK;
    ok &= MH_CreateHook(addr("WSARecv"), &Hook_WSARecv,
                        reinterpret_cast<LPVOID*>(&Real_WSARecv)) == MH_OK;
    ok &= MH_CreateHook(addr("connect"), &Hook_connect,
                        reinterpret_cast<LPVOID*>(&Real_connect)) == MH_OK;
    ok &= MH_CreateHook(addr("WSAConnect"), &Hook_WSAConnect,
                        reinterpret_cast<LPVOID*>(&Real_WSAConnect)) == MH_OK;

    if (ok) ok = MH_EnableHook(MH_ALL_HOOKS) == MH_OK;
    return ok;
}

// ---------------------------------------------------------------------------
// 界面
// ---------------------------------------------------------------------------
long GetEditInt(HWND edit, long defValue) {
    wchar_t buf[64] = {0};
    GetWindowTextW(edit, buf, 63);
    wchar_t* end = nullptr;
    long v = wcstol(buf, &end, 0);  // base 0:支持 0x 前缀
    return (end && end != buf) ? v : defValue;
}

void DoSendFrame() {
    int32_t a = static_cast<int32_t>(GetEditInt(g_edA, 0));
    int32_t b = static_cast<int32_t>(GetEditInt(g_edB, 0));

    // 协议固定值:cmd=0x01, type=0x0015, seq=3
    constexpr uint8_t cmd = 0x01;
    constexpr uint16_t ptype = 0x0015;
    constexpr uint16_t seq = 3;

    auto body = proto::make_body(a, b);
    auto frame = proto::game_frame(ptype, body, seq, cmd);

    LogFmt(L"发送: cmd=0x%02X type=0x%04X seq=%hu length=%u (A=%d B=%d)",
           cmd, ptype, seq, static_cast<uint32_t>(frame.size()), a, b);

    // 方案 3:只发给最近一次活跃的连接;发送前校验其仍然有效,失效则清理
    SOCKET s = GetLastActive();
    if (s == INVALID_SOCKET) {
        LogLine(L"[!] 尚未捕获目标连接(等待远端端口 10011 的 TCP 连接)...");
        return;
    }

    sockaddr_storage ss;
    int ssLen = sizeof(ss);
    if (getpeername(s, reinterpret_cast<sockaddr*>(&ss), &ssLen) != 0 ||
        !SockAddrIsTarget(reinterpret_cast<const sockaddr*>(&ss))) {
        LogLine(L"[!] 最近一次活跃的连接已失效,已将其清理;等待新的 10011 连接。");
        RemoveTarget(s);
        return;
    }

    int r = Real_send ? Real_send(s, reinterpret_cast<const char*>(frame.data()),
                                  static_cast<int>(frame.size()), 0)
                      : send(s, reinterpret_cast<const char*>(frame.data()),
                             static_cast<int>(frame.size()), 0);
    if (r == static_cast<int>(frame.size())) {
        LogFmt(L"[+] SOCKET=0x%IX(最近活跃)已发送 %zu 字节", s, frame.size());
    } else {
        LogFmt(L"[!] SOCKET=0x%IX 发送失败 ret=%d WSAGetLastError=%d", s, r,
               WSAGetLastError());
    }
}

void CreateControls(HWND hwnd) {
    HFONT font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
    auto label = [&](int x, int y, int w, const wchar_t* text) {
        HWND h = CreateWindowExW(0, L"STATIC", text, WS_CHILD | WS_VISIBLE,
                                 x, y, w, 18, hwnd, nullptr, g_hinst, nullptr);
        SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
        return h;
    };
    auto edit = [&](int x, int y, int w, const wchar_t* def) {
        HWND h = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", def,
                                 WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                 x, y, w, 22, hwnd, nullptr, g_hinst, nullptr);
        SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
        return h;
    };

    label(10, 12, 40, L"A:");       g_edA = edit(35, 10, 100, L"0");
    label(150, 12, 40, L"B:");      g_edB = edit(175, 10, 100, L"0");

    HWND btn = CreateWindowExW(0, L"BUTTON", L"发送",
                               WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                               10, 42, 80, 26, hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_SEND)),
                               g_hinst, nullptr);
    SendMessageW(btn, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);

    HWND hint = CreateWindowExW(0, L"STATIC",
        L"发送目标: 最近活跃的 10011 连接 | 固定: cmd=0x01 type=0x0015 seq=3",
        WS_CHILD | WS_VISIBLE, 100, 46, 640, 18, hwnd, nullptr, g_hinst, nullptr);
    SendMessageW(hint, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);

    g_log = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE |
                                ES_READONLY | ES_AUTOVSCROLL,
                            10, 76, 730, 330, hwnd, nullptr, g_hinst, nullptr);
    SendMessageW(g_log, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE:
            CreateControls(hwnd);
            return 0;
        case WM_COMMAND:
            if (LOWORD(wp) == IDC_SEND && HIWORD(wp) == BN_CLICKED)
                DoSendFrame();
            return 0;
        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;
        case WM_DESTROY:
            g_hwnd = nullptr;
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

bool CreateMainWindow() {
    WNDCLASSEXW wc;
    wc.cbSize = sizeof(wc);
    wc.style = 0;
    wc.lpfnWndProc = WndProc;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hInstance = g_hinst;
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszMenuName = nullptr;
    wc.lpszClassName = kClassName;
    wc.hIconSm = LoadIconW(nullptr, IDI_APPLICATION);
    if (!RegisterClassExW(&wc)) return false;

    g_hwnd = CreateWindowExW(0, kClassName,
                             L"A21 socket hook 控制台  (远端端口 10011)",
                             WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                             CW_USEDEFAULT, CW_USEDEFAULT, 766, 450,
                             nullptr, nullptr, g_hinst, nullptr);
    if (!g_hwnd) return false;

    ShowWindow(g_hwnd, SW_SHOW);
    UpdateWindow(g_hwnd);
    return true;
}

// ---------------------------------------------------------------------------
// 工作线程:UI 消息循环 + hook 安装(UI 线程内执行 hook,日志/发送都从该线程走)
// ---------------------------------------------------------------------------
DWORD WINAPI WorkerThread(LPVOID) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    if (!CreateMainWindow()) {
        // 界面起不来也保留 hook 能力由 send 兜底? 这里直接退出线程,不影响宿主。
        return 0;
    }

    if (InstallHooks()) {
        LogFmt(L"[+] hooks 已安装: send/WSASend/connect/WSAConnect/recv/WSARecv,目标远端端口 %hu",
               kTargetPort);
    } else {
        LogLine(L"[!] hook 安装失败(目标进程可能已加载冲突的 hook 库)");
    }

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    return 0;
}

}  // namespace

BOOL APIENTRY DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    (void)reserved;
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            g_hinst = hinst;
            DisableThreadLibraryCalls(hinst);
            InitializeCriticalSection(&g_cs);
            if (HANDLE t = CreateThread(nullptr, 0, WorkerThread, nullptr, 0, nullptr))
                CloseHandle(t);
            break;
        case DLL_PROCESS_DETACH:
            DeleteCriticalSection(&g_cs);
            break;
    }
    return TRUE;
}
