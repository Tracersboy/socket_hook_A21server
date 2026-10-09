# socket_hook_A21server

32 位 Windows socket hook 工具,用于测试自建服务(远端端口 **10011**)的协议安全性。

- **injector.exe**(32 位控制台程序):枚举进程,按进程名或 PID 选择目标,通过
  `CreateRemoteThread + LoadLibraryW` 注入 `A21hook.dll`。
- **A21hook.dll**(32 位):MinHook inline hook `ws2_32` 的
  `send / WSASend / connect / WSAConnect / recv / WSARecv`;捕获所有远端端口 = 10011 的
  TCP 连接 SOCKET 句柄(`connect` 建立时登记,`send` 时 `getpeername` 兜底过滤,晚注入也能抓到),
  并在目标进程内弹出控制窗口,可输入 A、B(及 cmd/type/seq)按 game 协议组包并发送,收发实时打日志。

> 仅供在你自己拥有或获授权的环境/服务器上使用。

## 协议(game 包)

```
cmd(1) + type(2) + length(4=帧总长) + checksum(4) + seq(2) + extra(1) + body
```

- 小端,header 共 14 字节;`length` 必须 = 帧总长(14 + len(body))。
- 服务端不校验 checksum / seq(checksum 填 0,extra 填 0)。
- 本项目固定值:**cmd=0x01,type=0x0015,seq=3**。
- 发送 body 为 `struct.pack("<iiii", A, B, 0, 0)`,A、B 由界面输入。

## 构建与发布

- push 到 `main`:Actions → **build** 工作流构建并上传产物 **socket_hook_x86**。
- 推送 `v*` 标签(如 `v1.0.0`):Actions → **release** 工作流构建、打包并自动创建
  GitHub Release,附 `socket_hook_x86.zip`。发布新版本只需:

  ```
  git tag v1.0.0 && git push origin v1.0.0
  ```

## 使用

1. 把 `injector.exe` 与 `A21hook.dll` 放在同一目录(或在界面里浏览指定 DLL 路径)。
2. 运行 `injector.exe`(建议「以管理员运行」,界面内有提权按钮):
   - 进程列表支持按名称/PID 关键字实时筛选;
   - 选中目标进程,点「注入」或双击列表项;
3. 注入成功后,目标进程内弹出 **A21 socket hook 控制台**窗口:
   - 目标程序连接远端端口 10011 时,日志区自动捕获并显示 `SOCKET` 句柄;
   - 输入 A、B,点击「发送」即按协议组包发出(cmd=0x01 / type=0x0015 / seq=3 为固定值,见 `gameproto.h`);
   - 所有经目标 SOCKET 的收发帧都会以 hex dump 显示在日志区。

命令行静默注入(不弹主窗口,结果用消息框提示):

```
injector.exe -p <进程名|PID> [-d C:\path\A21hook.dll]
```

## 子项目:exp_buy_item(独立 PoC 客户端,无 hook)

`expclient/exp_buy_item.cpp` 是 `exp_buy_item.py` 的 C++/Win32 图形化重写:不注入、不 hook,
独立 TCP 直连服务器,验证 BUY_ITEM(0x0015) 未校验商品上架关系 + 零价格免费入包漏洞
(仅限服务器所有者在自己的环境验证)。

- 界面输入(HOST / 端口 / 账号 / **明文密码** / 物品ID / 数量 / 选角slot)即 Python 版的可变参数,均有默认值;
- 密码不存哈希:客户端本地按 `a21-pbkdf2-sha256-v1`(salt=SHA256(PREFIX+"\0"+账号)[:16],
  PBKDF2-HMAC-SHA256,210000 轮,16B)计算,纯 C++ 实现(`expclient/pbkdf2_sha256.h`),
  CI 每次构建跑已知向量自检 `derive("wsw123","wsw123456")=9a01adb0…1965`;
- 流程与原版一致:banner → LOGIN(seq=1) → SELECT_CHAR(seq=2,slot 可改) → 排空同步包 →
  BUY_ITEM(seq=3,body=`<iiii>` itemId,count,0,0) → 等待 0x0015 ACK;
- 单 exe,32 位,后台线程执行,日志区实时显示收发。

## 子项目:cargo_dupe(账号金库复制 PoC,无 hook)

`expclient/cargo_dupe.cpp` 是 `cargo_maxexp.py` 的 C++/Win32 图形化重写:不注入、不 hook,
独立 TCP 直连服务器,验证账号金库(AccountCargo)双角色快照不一致导致的金币/物品复制漏洞
(仅限服务器所有者在自己的环境验证)。

- **机制**:同账号双角色同时在线,各自持有选角时载入的金库内存快照;账号金库无账号级互斥,
  落库无条件覆盖 → 后取者基于陈旧快照再取一次,一份资产发两次。
- 界面输入(HOST / 端口 / 账号 / **明文密码** / 物品ID / 目标数量);密码本地 PBKDF2 派生(同上)。
- 两个功能:**金币复制**(两角色金币全部入金库做本金,每轮金库翻倍,复制一次超 int32 即停)、
  **物品复制**(指定 itemId + 目标数量,整栈复利增长到满栈,之后每轮净增一整栈,产出留金库)。
- 状态全部来自服务端回包(选角后 `ITEM_LIST` noti 0x000D + 存/取 ack 带新金库值),**不读数据库**;
  MOVE ack 解析服务端归一化落点做簿记;快捷槽物品(3-8)用「金库往返 + 逐区间试探」可逆探测 kind。
- 自动探测 slot 0-5 选角、缺角色自动建 duptest2;重选角(SELECT_CHAR)重载快照,异常自动降级整线重登;
  完整日志输出每一步;后台线程执行,可随时停止。

## 目录结构

```
├── CMakeLists.txt          # 顶层工程(强制 32 位,FetchContent 拉取 MinHook v1.3.4)
├── .github/workflows/      # CI:MSVC x86 构建 + 产物打包;v* 标签自动发 Release
├── injector/injector.cpp   # 图形化注入器(进程列表/筛选/注入/日志;支持 -p 静默注入)
├── hookdll/
│   ├── dllmain.cpp         # hooks + 控制窗口 + 发送逻辑
│   └── gameproto.h         # game 协议组包(game_frame / make_body),PoC 客户端复用
└── expclient/
    ├── exp_buy_item.cpp    # 独立 PoC 客户端图形版(BUY_ITEM 0x0015 验证)
    ├── cargo_dupe.cpp      # 独立 PoC 客户端图形版(账号金库金币/物品复制验证)
    ├── pbkdf2_sha256.h     # A21 口令哈希纯 C++ 实现(SHA-256/HMAC/PBKDF2)
    └── hash_selftest.cpp   # 口令哈希已知向量自检(CI 每构建必跑)
```
