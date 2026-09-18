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

#include "SeedGenerator.hpp"

#include <cstring>
#include <memory>
#include <mutex>
#include <random>

namespace deb {

namespace {
// Guards the singleton's RNG state: both Gen() and Reseed() mutate it, and
// either may be called concurrently from user threads.
std::mutex g_rng_mutex;

RNGSeed makeEntropySeed() {
    std::random_device rd;
    RNGSeed seed = {};
    for (size_t i = 0; i < seed.size(); ++i) {
        auto ptr = reinterpret_cast<unsigned int *>(&seed[i]);
        for (size_t j = 0; j < sizeof(u64) / sizeof(unsigned int); ++j) {
            ptr[j] = rd();
        }
    }
    return seed;
}
} // namespace

SeedGenerator &SeedGenerator::GetInstance(const std::optional<RNGSeed> &seed) {
    static SeedGenerator instance(seed);
    return instance;
}
void SeedGenerator::Reseed(const std::optional<RNGSeed> &seed) {
    const RNGSeed s = seed ? *seed : makeEntropySeed();
    SeedGenerator &instance = GetInstance();
    std::lock_guard<std::mutex> lock(g_rng_mutex);
    instance.rng_->reseed(reinterpret_cast<const u8 *>(s.data()),
                          DEB_RNG_SEED_BYTE_SIZE);
}

RNGSeed SeedGenerator::Gen() { return GetInstance().genSeed(); }

SeedGenerator::SeedGenerator(const std::optional<RNGSeed> &seed)
    : rng_(createRandomGenerator(seed ? *seed : makeEntropySeed())) {}

RNGSeed SeedGenerator::genSeed() {
    RNGSeed seed = {};
    std::lock_guard<std::mutex> lock(g_rng_mutex);
    rng_->getRandomUint64Array(seed.data(), DEB_U64_SEED_SIZE);
    return seed;
}

} // namespace deb
