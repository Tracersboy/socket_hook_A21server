// pbkdf2_sha256.h
// A21 口令哈希的纯 C++ 实现(无第三方依赖):
//
//   PREFIX = "a21-pbkdf2-sha256-v1", ITERATIONS = 210000, SALT 16B, KEY 16B
//   salt = SHA256(PREFIX + "\0" + account.strip().lower())[:16]
//   hash = PBKDF2-HMAC-SHA256(password_utf8, salt, 210000, dklen=16).hex()
//
// 校验向量:derive("demo", "demo123456") == "3fa6167e893745d4be5febeca85f6bc7"
// (见 hash_selftest.cpp,CI 每次构建都会跑)
#pragma once

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace a21hash {

// ---------------------------------------------------------------------------
// SHA-256
// ---------------------------------------------------------------------------
class Sha256 {
public:
    Sha256() { reset(); }

    void update(const uint8_t* data, size_t len) {
        totalBits_ += static_cast<uint64_t>(len) * 8;
        for (size_t i = 0; i < len; ++i) addByte(data[i]);
    }

    void update(const std::string& s) {
        update(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    }

    std::array<uint8_t, 32> final() {
        const uint64_t bits = totalBits_;
        addByte(0x80);
        while (bufLen_ != 56) addByte(0x00);
        uint8_t lenBytes[8];
        for (int i = 0; i < 8; ++i)
            lenBytes[i] = static_cast<uint8_t>((bits >> (56 - 8 * i)) & 0xFF);
        for (int i = 0; i < 8; ++i) addByte(lenBytes[i]);

        std::array<uint8_t, 32> out;
        for (int i = 0; i < 8; ++i)
            for (int j = 0; j < 4; ++j)
                out[i * 4 + j] = static_cast<uint8_t>((h_[i] >> (24 - 8 * j)) & 0xFF);
        return out;
    }

    static std::array<uint8_t, 32> digest(const std::string& s) {
        Sha256 ctx;
        ctx.update(s);
        return ctx.final();
    }

private:
    uint32_t h_[8];
    std::array<uint8_t, 64> buf_;
    size_t bufLen_ = 0;
    uint64_t totalBits_ = 0;

    void reset() {
        h_[0] = 0x6a09e667; h_[1] = 0xbb67ae85; h_[2] = 0x3c6ef372; h_[3] = 0xa54ff53a;
        h_[4] = 0x510e527f; h_[5] = 0x9b05688c; h_[6] = 0x1f83d9ab; h_[7] = 0x5be0cd19;
        bufLen_ = 0;
        totalBits_ = 0;
    }

    void addByte(uint8_t b) {
        buf_[bufLen_++] = b;
        if (bufLen_ == 64) {
            transform(buf_.data());
            bufLen_ = 0;
        }
    }

    static uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }

    void transform(const uint8_t* p) {
        static const uint32_t K[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
            0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
            0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
            0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
            0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (static_cast<uint32_t>(p[i * 4]) << 24) |
                   (static_cast<uint32_t>(p[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(p[i * 4 + 2]) << 8) |
                   static_cast<uint32_t>(p[i * 4 + 3]);
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
        uint32_t e = h_[4], f = h_[5], g = h_[6], h = h_[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = h + s1 + ch + K[i] + w[i];
            uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = s0 + maj;
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d;
        h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += h;
    }
};

// ---------------------------------------------------------------------------
// HMAC-SHA256
// ---------------------------------------------------------------------------
inline std::array<uint8_t, 32> HmacSha256(const uint8_t* key, size_t keyLen,
                                          const uint8_t* msg, size_t msgLen) {
    uint8_t k[64] = {0};
    if (keyLen > 64) {
        auto d = Sha256::digest(std::string(reinterpret_cast<const char*>(key), keyLen));
        std::memcpy(k, d.data(), 32);
    } else if (keyLen > 0) {
        std::memcpy(k, key, keyLen);
    }

    uint8_t pad[128];
    for (int i = 0; i < 64; ++i) {
        pad[i] = k[i] ^ 0x36;        // ipad
        pad[64 + i] = k[i] ^ 0x5c;   // opad
    }

    Sha256 inner;
    inner.update(pad, 64);
    inner.update(msg, msgLen);
    auto innerDigest = inner.final();

    Sha256 outer;
    outer.update(pad + 64, 64);
    outer.update(innerDigest.data(), innerDigest.size());
    return outer.final();
}

// ---------------------------------------------------------------------------
// PBKDF2-HMAC-SHA256(RFC 2898,单分块路径已够用,这里给通用实现)
// ---------------------------------------------------------------------------
inline std::vector<uint8_t> Pbkdf2HmacSha256(const std::string& password,
                                             const uint8_t* salt, size_t saltLen,
                                             uint32_t iterations, size_t dkLen) {
    const size_t hLen = 32;
    const size_t blocks = (dkLen + hLen - 1) / hLen;
    std::vector<uint8_t> out;
    out.reserve(blocks * hLen);

    for (size_t block = 1; block <= blocks; ++block) {
        uint8_t saltBlock[128];
        std::memcpy(saltBlock, salt, saltLen);
        saltBlock[saltLen + 0] = static_cast<uint8_t>((block >> 24) & 0xFF);
        saltBlock[saltLen + 1] = static_cast<uint8_t>((block >> 16) & 0xFF);
        saltBlock[saltLen + 2] = static_cast<uint8_t>((block >> 8) & 0xFF);
        saltBlock[saltLen + 3] = static_cast<uint8_t>(block & 0xFF);

        const uint8_t* pw = reinterpret_cast<const uint8_t*>(password.data());
        auto u = HmacSha256(pw, password.size(), saltBlock, saltLen + 4);
        std::array<uint8_t, 32> t = u;
        for (uint32_t i = 1; i < iterations; ++i) {
            u = HmacSha256(pw, password.size(), u.data(), u.size());
            for (size_t j = 0; j < hLen; ++j) t[j] ^= u[j];
        }
        out.insert(out.end(), t.begin(), t.end());
    }
    out.resize(dkLen);
    return out;
}

// ---------------------------------------------------------------------------
// A21 口令哈希:账号转小写去空白, salt=SHA256(PREFIX+"\0"+acc)[:16],
// PBKDF2-HMAC-SHA256(password, salt, 210000, 16) → 小写 hex
// ---------------------------------------------------------------------------
inline std::string Derive(const std::string& account, const std::string& password) {
    static const char* kPrefix = "a21-pbkdf2-sha256-v1";
    constexpr uint32_t kIterations = 210000;
    constexpr size_t kSaltBytes = 16;
    constexpr size_t kKeyBytes = 16;

    // account.strip().lower()(ASCII 空白 + ASCII 大小写)
    size_t b = account.find_first_not_of(" \t\r\n");
    size_t e = account.find_last_not_of(" \t\r\n");
    std::string acc = (b == std::string::npos) ? std::string() : account.substr(b, e - b + 1);
    for (auto& ch : acc)
        if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');

    std::string saltInput(kPrefix);
    saltInput.push_back('\0');
    saltInput += acc;
    auto saltFull = Sha256::digest(saltInput);

    auto key = Pbkdf2HmacSha256(password, saltFull.data(), kSaltBytes, kIterations, kKeyBytes);

    static const char* hex = "0123456789abcdef";
    std::string out(key.size() * 2, '0');
    for (size_t i = 0; i < key.size(); ++i) {
        out[i * 2] = hex[(key[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[key[i] & 0xF];
    }
    return out;
}

}  // namespace a21hash
