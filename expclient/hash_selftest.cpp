// hash_selftest.cpp
// a21hash::Derive 的 CI 自检:校验向量 derive("wsw123", "wsw123456")
// 必须等于 9a01adb03d863718c3e8c9c4c1821965,否则返回非 0 使构建失败。
#include <cstdio>
#include <string>

#include "pbkdf2_sha256.h"

int main() {
    const std::string expect = "9a01adb03d863718c3e8c9c4c1821965";
    const std::string got = a21hash::Derive("wsw123", "wsw123456");
    if (got != expect) {
        std::printf("FAIL\n  expect: %s\n  got   : %s\n", expect.c_str(), got.c_str());
        return 1;
    }
    std::printf("OK  derive(\"wsw123\", \"wsw123456\") = %s\n", got.c_str());
    return 0;
}
