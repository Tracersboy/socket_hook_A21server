cmake_minimum_required(VERSION 3.20)
project(socket_hook_A21server LANGUAGES CXX)

# 注入器与 DLL 必须和目标进程位数一致:本项目仅支持 32 位 (x86)。
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(FATAL_ERROR "This project must be built as 32-bit (-A Win32).")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    # 源码为 UTF-8:告诉 MSVC 按 UTF-8 解析源码并生成正确的中文宽字符串字面量
    add_compile_options(/utf-8)
endif()

include(FetchContent)
FetchContent_Declare(
    minhook
    GIT_REPOSITORY https://github.com/TsudaKageyu/minhook.git
    GIT_TAG v1.3.4  # v1.3.3 标签不含 CMakeLists.txt,会导致链接找不到 minhook.lib
)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(minhook)

# 被注入的 DLL:MinHook hooks + 内嵌控制界面 + game 协议组包
add_library(A21hook SHARED
    hookdll/dllmain.cpp
    hookdll/gameproto.h
)
target_link_libraries(A21hook PRIVATE minhook ws2_32 comctl32)
target_include_directories(A21hook PRIVATE ${minhook_SOURCE_DIR}/include)

# 注入器(图形界面程序,WIN32 子系统,入口 wWinMain)
add_executable(injector WIN32 injector/injector.cpp)
target_link_libraries(injector PRIVATE comctl32 shell32 advapi32)

# exp_buy_item:独立 TCP 客户端版 PoC 的图形化重写(无需 hook/DLL 注入)
# 复用 hookdll/gameproto.h 的组包逻辑
add_executable(exp_buy_item WIN32 expclient/exp_buy_item.cpp)
target_link_libraries(exp_buy_item PRIVATE ws2_32)
target_include_directories(exp_buy_item PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/hookdll
    ${CMAKE_CURRENT_SOURCE_DIR}/expclient)

# cargo_dupe:账号金库(AccountCargo)金币/物品复制 PoC 的图形化重写
# 状态全部来自服务端回包(ITEM_LIST/ack),不读数据库;逻辑对齐 expclient/../cargo_maxexp.py
add_executable(cargo_dupe WIN32 expclient/cargo_dupe.cpp)
target_link_libraries(cargo_dupe PRIVATE ws2_32)
target_include_directories(cargo_dupe PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/hookdll
    ${CMAKE_CURRENT_SOURCE_DIR}/expclient)

# 口令哈希自检:derive("demo","demo123456") 必须等于已知向量,CI 每次构建都跑
add_executable(hash_selftest expclient/hash_selftest.cpp)
target_include_directories(hash_selftest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/expclient)
