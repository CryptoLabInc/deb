/*
 * Copyright 2026 CryptoLab, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "utils/Constant.hpp"
#include "utils/RandomGenerator.hpp"
#include "blake3.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <numeric>
#include <stdexcept>
#include <vector>

namespace deb {

class Blake3RandomGenerator : public RandomGenerator {
public:
    explicit Blake3RandomGenerator(const RNGSeed& seed) {
        reseed(reinterpret_cast<const u8 *>(seed.data()),
            DEB_RNG_SEED_BYTE_SIZE);
    }

    Blake3RandomGenerator(const Blake3RandomGenerator&) = delete;
    Blake3RandomGenerator& operator=(const Blake3RandomGenerator&) = delete;

    void getRandomUint64Array(u64* dst, size_t len) override {
        for (size_t i = 0; i < len; ++i) {
            u8 tmp[8];
            getBytes(tmp, sizeof(tmp));
            dst[i] = load_le_u64(tmp);
        }
    }
    void getRandomUint64ArrayInRange(u64* dst, size_t len, u64 range) override {
        if (range == 0) {
            std::memset(dst, 0, sizeof(u64) * len);
            return;
        }
        for (size_t i = 0; i < len; ++i) {
            dst[i] = uniform_u64_range(range);
        }
    }

    void sampleGaussianInt64Array(i64* dst, size_t len, double stdev) override {
        if (!(stdev > 0.0)) throw std::invalid_argument("stdev must be > 0");

        // Box-Muller
        size_t i = 0;
        while (i < len) {
            double u1 = uniform01();
            double u2 = uniform01();
            // avoid log(0)
            if (u1 <= 0.0) continue;

            double r = std::sqrt(-2.0 * std::log(u1));
            double theta = 2.0 * utils::REAL_PI * u2;

            double z0 = r * std::cos(theta) * stdev;
            double z1 = r * std::sin(theta) * stdev;

            dst[i++] = static_cast<i64>(std::llround(z0));
            if (i < len) dst[i++] = static_cast<i64>(std::llround(z1));
        }
    }
    void sampleHwtInt8Array(i8* dst, size_t len, int hwt) override {
        if (hwt < 0 || static_cast<size_t>(hwt) > len)
            throw std::invalid_argument("hwt must be in [0, len]");

        std::memset(dst, 0, len);

        std::vector<size_t> idx(len);
        for (size_t i = 0; i < len; ++i)
            idx[i] = i;

        // Fisher-Yates shuffle for first hwt indices, and assign +1/-1 randomly
        for (int i = 0; i < hwt; ++i) {
            u64 r = uniform_u64_range(len - i);
            size_t k = i + static_cast<size_t>(r);
            std::swap(idx[i], idx[k]);
            dst[idx[i]] = uniform_u64_range(2) ? 1 : -1;
        }
    }

    void reseed(const u8* seed, size_t seed_len) override {
        // hard-coded context string
        static constexpr const char* kContext =
            "example.random 2026-02-13 blake3-prng v1";

        blake3_hasher h;
        blake3_hasher_init_derive_key(&h, kContext);
        if (seed && seed_len) blake3_hasher_update(&h, seed, seed_len);
        blake3_hasher_finalize(&h, key_.data(), key_.size());

        counter_ = 0;
        buf_pos_ = kBufSize; // flush
        // internal use counter=0 when first refill
    }

private:
    // 32 bytes key (keyed hashing mode requirement)
    std::array<u8, BLAKE3_KEY_LEN> key_{};

    // Counter-based block generation
    u64 counter_ = 0;

    // Byte buffering (performance defense against many small calls)
    static constexpr size_t kBufSize = 4096;
    std::array<u8, kBufSize> buf_{};
    size_t buf_pos_ = kBufSize; // empty

    void refill() {
        // hashing (domain || counter) message with keyed hashing,
        // and output kBufSize bytes stream with finalize_seek.
        // Using seek=0 and counter to make independent stream.
        const u8 domain[] = {
            'B','L','A','K','E','3','-','P','R','N','G','-','v','1', 0x00
        };

        u8 ctr_le[8];
        store_le_u64(ctr_le, counter_);

        blake3_hasher h;
        blake3_hasher_init_keyed(&h, key_.data());
        blake3_hasher_update(&h, domain, sizeof(domain));
        blake3_hasher_update(&h, ctr_le, sizeof(ctr_le));

        // from seek=0, kBufSize bytes
        blake3_hasher_finalize_seek(&h, /*seek=*/0, buf_.data(), buf_.size());

        counter_++;
        buf_pos_ = 0;

        // optionally rekey every refill to enhance forward-secrecy-ish property.
        // Here we do not do light rekeying every refill,
        // let caller do periodic reseed or call rekey() if needed.
    }
    void getBytes(void* out, size_t n) {
        u8* p = static_cast<u8*>(out);
        while (n) {
            if (buf_pos_ >= buf_.size()) refill();
            size_t avail = buf_.size() - buf_pos_;
            size_t take = (n < avail) ? n : avail;
            std::memcpy(p, buf_.data() + buf_pos_, take);
            buf_pos_ += take;
            p += take;
            n -= take;
        }
    }

    static u64 load_le_u64(const u8* p) {
        u64 x = 0;
        for (int i = 7; i >= 0; --i) x = (x << 8) | p[i];
        return x;
    }

    static void store_le_u64(u8* p, u64 x) {
        for (int i = 0; i < 8; ++i) { p[i] = static_cast<u8>(x & 0xFF); x >>= 8; }
    }

    // [0,1) double (53-bit) generation
    double uniform01() {
        u8 tmp[8];
        getBytes(tmp, sizeof(tmp));
        u64 x = load_le_u64(tmp);
        x >>= 11; // 64-53
        // [0, 2^53) / 2^53
        constexpr double denom = 9007199254740992.0; // 2^53
        return static_cast<double>(x) / denom;
    }

    // [0, range) unbiased
    u64 uniform_u64_range(u64 range) {
        if (range == 0) return 0; // caller bug defense
        // rejection sampling (unbiased)
        const u64 max = std::numeric_limits<u64>::max();
        const u64 limit = max - (max % range);
        while (true) {
            u8 tmp[8];
            getBytes(tmp, sizeof(tmp));
            u64 x = load_le_u64(tmp);
            if (x < limit) return x % range;
        }
    }

    // Rekey (re-extract key from output stream to enhance forward-secrecy-ish property)
    void rekey() {
        std::array<u8, BLAKE3_KEY_LEN> new_key{};
        getBytes(new_key.data(), new_key.size());
        key_ = new_key;

        // Flush buffer and start fresh with new key
        buf_pos_ = kBufSize;
        counter_ = 0;
    }
};

std::shared_ptr<RandomGenerator> createBlake3RandomGenerator(const RNGSeed& seed) {
    return std::make_shared<Blake3RandomGenerator>(seed);
};

} // namespace deb
