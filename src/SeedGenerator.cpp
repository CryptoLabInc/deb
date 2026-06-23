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
#include <random>

namespace deb {

SeedGenerator &SeedGenerator::GetInstance(const std::optional<RNGSeed> &seed) {
    static SeedGenerator instance(seed);
    return instance;
}
void SeedGenerator::Reseed(const std::optional<RNGSeed> &seed) {
    const auto &s = seed.value();
    GetInstance().rng_->reseed(reinterpret_cast<const u8 *>(s.data()),
                               DEB_RNG_SEED_BYTE_SIZE);
}

RNGSeed SeedGenerator::Gen() { return GetInstance().genSeed(); }

SeedGenerator::SeedGenerator(const std::optional<RNGSeed> &seed) {
    if (!seed) {
        std::random_device rd;
        RNGSeed nseed = {};
        for (size_t i = 0; i < nseed.size(); ++i) {
            auto ptr = reinterpret_cast<unsigned int *>(&nseed[i]);
            for (size_t j = 0; j < sizeof(u64) / sizeof(unsigned int); ++j) {
                ptr[j] = rd();
            }
        }
        rng_ = createRandomGenerator(nseed);
    } else {
        rng_ = createRandomGenerator(seed.value());
    }
}

RNGSeed SeedGenerator::genSeed() {
    RNGSeed seed = {};
    rng_->getRandomUint64Array(seed.data(), DEB_U64_SEED_SIZE);
    return seed;
}

} // namespace deb
