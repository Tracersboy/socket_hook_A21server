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
- 发送 body 为 `struct.pack("<iiii", A, B, 0, 0)`,A、B 由界面输入。

## 构建与发布

- push 到 `main`:Actions → **build** 工作流构建并上传产物 **socket_hook_x86**。
- 推送 `v*` 标签(如 `v1.0.0`):Actions → **release** 工作流构建、打包并自动创建
  GitHub Release,附 `socket_hook_x86.zip`。发布新版本只需:

  ```
  git tag v1.0.0 && git push origin v1.0.0
  ```

## 使用

1. 把 `injector.exe` 与 `A21hook.dll` 放在同一目录(或以 `-d` 指定 DLL 路径)。
2. 以**管理员**运行 `injector.exe`,输入目标进程名(部分匹配)或 PID。
3. 注入成功后,目标进程内弹出 **A21 socket hook 控制台**窗口:
   - 目标程序连接远端端口 10011 时,日志区自动捕获并显示 `SOCKET` 句柄;
   - 输入 A、B,点击「发送」即按协议组包发出;cmd(默认 `0x15`)/type(默认 `0x0015`)/seq(默认 `3`)可改;
   - 所有经目标 SOCKET 的收发帧都会以 hex dump 显示在日志区。

命令行方式:

```
injector.exe -p <进程名|PID> [-d C:\path\A21hook.dll]
```

## 目录结构

```
├── CMakeLists.txt          # 顶层工程(强制 32 位,FetchContent 拉取 MinHook v1.3.3)
├── .github/workflows/      # CI:MSVC x86 构建 + 产物打包
├── injector/injector.cpp   # 注入器
└── hookdll/
    ├── dllmain.cpp         # hooks + 控制窗口 + 发送逻辑
    └── gameproto.h         # game 协议组包(game_frame / make_body)
```
