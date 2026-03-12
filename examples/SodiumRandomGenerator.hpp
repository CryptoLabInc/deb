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

#include <sodium.h>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <numeric>
#include <stdexcept>
#include <vector>

namespace deb {

// ---------------------------------------------------------------------------
// SodiumRandomGenerator — a custom RandomGenerator backed by libsodium.
//
// Internally it derives a 32-byte ChaCha20 key from the 64-byte RNGSeed
// via BLAKE2b (crypto_generichash) and uses crypto_stream_xchacha20 with
// an incrementing 24-byte nonce to produce a deterministic byte stream.
// ---------------------------------------------------------------------------
class SodiumRandomGenerator : public RandomGenerator {
public:
    explicit SodiumRandomGenerator(const RNGSeed &seed) {
        if (sodium_init() < 0) {
            throw std::runtime_error(
                "[SodiumRandomGenerator] sodium_init failed");
        }
        deriveSeedMaterial(reinterpret_cast<const u8 *>(seed.data()),
                           DEB_RNG_SEED_BYTE_SIZE);
    }

    SodiumRandomGenerator(const SodiumRandomGenerator &) = delete;
    SodiumRandomGenerator &operator=(const SodiumRandomGenerator &) = delete;

    ~SodiumRandomGenerator() override { sodium_memzero(key_, sizeof(key_)); }

    // -- basic random generation --------------------------------------------

    void getRandomUint64Array(u64 *dst, size_t len) override {
        fillBytes(reinterpret_cast<u8 *>(dst), len * sizeof(u64));
    }

    void getRandomUint64ArrayInRange(u64 *dst, size_t len,
                                     u64 range) override {
        for (size_t i = 0; i < len; ++i) {
            dst[i] = uniformUint64InRange(range);
        }
    }

    // -- distribution sampling ----------------------------------------------

    void sampleGaussianInt64Array(i64 *dst, size_t len,
                                  double stdev) override {
        // Box-Muller transform, consuming two uniform doubles per pair.
        size_t i = 0;
        while (i + 1 < len) {
            double u1, u2;
            uniformDouble01(u1, u2);
            double r = stdev * std::sqrt(-2.0 * std::log(u1));
            dst[i] =
                static_cast<i64>(std::round(r * std::cos(2.0 * utils::REAL_PI * u2)));
            dst[i + 1] =
                static_cast<i64>(std::round(r * std::sin(2.0 * utils::REAL_PI * u2)));
            i += 2;
        }
        if (i < len) {
            double u1, u2;
            uniformDouble01(u1, u2);
            double r = stdev * std::sqrt(-2.0 * std::log(u1));
            dst[i] =
                static_cast<i64>(std::round(r * std::cos(2.0 * utils::REAL_PI * u2)));
        }
    }

    void sampleHwtInt8Array(i8 *dst, size_t len, int hwt) override {
        // Fill with zeros, place +1/-1 at `hwt` random positions.
        std::memset(dst, 0, len);

        // Build index array and shuffle first `hwt` positions (Fisher-Yates).
        std::vector<size_t> indices(len);
        std::iota(indices.begin(), indices.end(), 0);

        for (int i = 0; i < hwt; ++i) {
            u64 j_raw;
            fillBytes(reinterpret_cast<u8 *>(&j_raw), sizeof(j_raw));
            size_t j = i + static_cast<size_t>(j_raw % (len - i));
            std::swap(indices[i], indices[j]);

            // Random sign: use one bit.
            u8 sign_byte;
            fillBytes(&sign_byte, 1);
            dst[indices[i]] = (sign_byte & 1) ? 1 : -1;
        }
    }

    void reseed(const u8 *seed, size_t seed_len) override {
        deriveSeedMaterial(seed, seed_len);
    }

private:
    void deriveSeedMaterial(const u8 *seed, size_t seed_len) {
        // BLAKE2b-512 -> first 32 bytes = key, next 24 bytes = initial nonce.
        u8 hash[64];
        crypto_generichash(hash, sizeof(hash), seed, seed_len, nullptr, 0);
        std::memcpy(key_, hash, crypto_stream_xchacha20_KEYBYTES);
        std::memset(nonce_, 0, sizeof(nonce_));
        std::memcpy(nonce_, hash + 32,
                    std::min<size_t>(24, sizeof(hash) - 32));
        sodium_memzero(hash, sizeof(hash));
    }

    void fillBytes(u8 *buf, size_t buflen) {
        crypto_stream_xchacha20(buf, buflen, nonce_, key_);
        incrementNonce();
    }

    void incrementNonce() { sodium_increment(nonce_, sizeof(nonce_)); }

    u64 uniformUint64InRange(u64 range) {
        // Rejection sampling for uniform distribution in [0, range).
        if (range <= 1)
            return 0;
        u64 limit = (UINT64_MAX / range) * range;
        u64 val;
        do {
            fillBytes(reinterpret_cast<u8 *>(&val), sizeof(val));
        } while (val >= limit);
        return val % range;
    }

    void uniformDouble01(double &a, double &b) {
        // Generate two doubles in (0, 1] using 52-bit mantissa.
        u64 raw[2];
        fillBytes(reinterpret_cast<u8 *>(raw), sizeof(raw));
        a = static_cast<double>((raw[0] >> 12) + 1) / 4503599627370496.0;
        b = static_cast<double>((raw[1] >> 12) + 1) / 4503599627370496.0;
    }

    u8 key_[crypto_stream_xchacha20_KEYBYTES];
    u8 nonce_[crypto_stream_xchacha20_NONCEBYTES];
};

} // namespace deb
