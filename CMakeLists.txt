cmake_minimum_required(VERSION 3.20)
project(socket_hook_A21server LANGUAGES CXX)

# 注入器与 DLL 必须和目标进程位数一致:本项目仅支持 32 位 (x86)。
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(FATAL_ERROR "This project must be built as 32-bit (-A Win32).")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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
