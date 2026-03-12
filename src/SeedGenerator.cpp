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

SeedGenerator &SeedGenerator::GetInstance(std::optional<const RNGSeed> seeds) {
    static SeedGenerator instance(seeds);
    return instance;
}
void SeedGenerator::Reseed(const std::optional<const RNGSeed> &seeds) {
    const auto &s = seeds.value();
    GetInstance().rng_->reseed(reinterpret_cast<const u8 *>(s.data()),
                               DEB_RNG_SEED_BYTE_SIZE);
}

RNGSeed SeedGenerator::Gen() { return GetInstance().genSeed(); }

SeedGenerator::SeedGenerator(std::optional<const RNGSeed> seeds) {
    if (!seeds) {
        std::random_device rd;
        RNGSeed nseeds;
        for (size_t i = 0; i < nseeds.size(); ++i) {
            auto ptr = reinterpret_cast<unsigned int *>(&nseeds[i]);
            for (size_t j = 0; j < sizeof(u64) / sizeof(unsigned int); ++j) {
                ptr[j] = rd();
            }
        }
        seeds.emplace(nseeds);
    }
    rng_ = createRandomGenerator(seeds.value());
}

RNGSeed SeedGenerator::genSeed() {
    RNGSeed seeds;
    rng_->getRandomUint64Array(seeds.data(), DEB_U64_SEED_SIZE);
    return seeds;
}

} // namespace deb
