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

#include "Types.hpp"

#include <array>
#include <functional>
#include <memory>

namespace deb {

constexpr size_t DEB_RNG_SEED_BYTE_SIZE = 64;
constexpr size_t DEB_U64_SEED_SIZE = DEB_RNG_SEED_BYTE_SIZE / sizeof(u64);

using RNGSeed = std::array<u64, DEB_U64_SEED_SIZE>;

class RandomGenerator {
public:
    virtual ~RandomGenerator() = default;

    virtual void getRandomUint64Array(u64 *dst, size_t len) = 0;
    virtual void getRandomUint64ArrayInRange(u64 *dst, size_t len,
                                             u64 range) = 0;

    virtual void sampleGaussianInt64Array(i64 *dst, size_t len,
                                          double stdev) = 0;
    virtual void sampleHwtInt8Array(i8 *dst, size_t len, int hwt) = 0;

    virtual void reseed(const u8 *seed, size_t seed_len) = 0;
};

using RandomGeneratorFactory =
    std::function<std::shared_ptr<RandomGenerator>(const RNGSeed &seed)>;

void setRandomGeneratorFactory(RandomGeneratorFactory factory);
std::shared_ptr<RandomGenerator> createRandomGenerator(const RNGSeed &seed);

} // namespace deb
