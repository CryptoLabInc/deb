/*
 * Copyright 2025 CryptoLab, Inc.
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

const u8 *to_alea_seed(const RNGSeed &seed) {
    return reinterpret_cast<const u8 *>(seed.data());
}

SeedGenerator &SeedGenerator::GetInstance(std::optional<const RNGSeed> seeds) {
    static SeedGenerator instance(seeds);
    return instance;
}
void SeedGenerator::Reseed(const std::optional<const RNGSeed> &seeds) {
    alea_reseed(GetInstance().as_.get(), to_alea_seed(seeds.value()));
}

RNGSeed SeedGenerator::Gen() { return GetInstance().genSeed(); }

SeedGenerator::SeedGenerator(std::optional<const RNGSeed> seeds)
    : as_(nullptr, &alea_free) {
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
    alea_state *p = alea_init(reinterpret_cast<const u8 *>(seeds->data()),
                              ALEA_ALGORITHM_SHAKE256);
    as_ = std::unique_ptr<alea_state, decltype(&alea_free)>(p, &alea_free);
}

RNGSeed SeedGenerator::genSeed() {
    RNGSeed seeds;
    alea_get_random_uint64_array(as_.get(), seeds.data(), DEB_U64_SEED_SIZE);
    return seeds;
}

} // namespace deb
