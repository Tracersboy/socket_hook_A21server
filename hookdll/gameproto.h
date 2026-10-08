// gameproto.h
// game 协议组包,与 Python 侧 struct.pack("<BHI I HB", ...) 布局一致:
//
//   客户端->服务端 game 包:
//     cmd(1) + type(2) + length(4=帧总长) + checksum(4) + seq(2) + extra(1) + body
//     小端;headerSize = 14;length 必须 = 帧总长(14 + len(body));
//     服务端不校验 checksum/seq(checksum 填 0,extra 填 0)。
//
// Python 参考:
//   total = 14 + len(body)
//   frame = struct.pack("<BHI", CMD, ptype, total) + struct.pack("<I", 0) \
//           + struct.pack("<HB", seq & 0xFFFF, 0) + body
//   body  = struct.pack("<iiii", A, B, 0, 0)
#pragma once

#include <cstdint>
#include <vector>

namespace proto {

inline constexpr uint8_t kHeaderSize = 14;

// 组一帧 game 包。
//   cmd   - 1 字节命令字,本项目固定 0x01
//   ptype - 2 字节类型,本项目固定 0x0015
//   seq   - 2 字节序号,本项目固定 3(服务端不校验)
inline std::vector<uint8_t> game_frame(uint16_t ptype, const std::vector<uint8_t>& body,
                                       uint16_t seq = 0, uint8_t cmd = 0x01) {
    const uint32_t total = kHeaderSize + static_cast<uint32_t>(body.size());
    std::vector<uint8_t> out;
    out.reserve(total);

    auto push16 = [&out](uint16_t v) {
        out.push_back(static_cast<uint8_t>(v & 0xFF));
        out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    };
    auto push32 = [&out](uint32_t v) {
        for (int i = 0; i < 4; ++i)
            out.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
    };

    out.push_back(cmd);   // cmd(1)
    push16(ptype);        // type(2)
    push32(total);        // length(4) = 帧总长
    push32(0);            // checksum(4),不校验,填 0
    push16(seq);          // seq(2)
    out.push_back(0);     // extra(1)

    out.insert(out.end(), body.begin(), body.end());
    return out;
}

// body = struct.pack("<iiii", A, B, 0, 0),16 字节小端有符号 int32。
inline std::vector<uint8_t> make_body(int32_t a, int32_t b) {
    std::vector<uint8_t> body(16, 0);
    auto put32 = [&body](size_t off, int32_t v) {
        uint32_t u = static_cast<uint32_t>(v);
        for (int i = 0; i < 4; ++i)
            body[off + i] = static_cast<uint8_t>((u >> (8 * i)) & 0xFF);
    };
    put32(0, a);
    put32(4, b);
    // 8..15 恒为 0
    return body;
}

}  // namespace proto
