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

#include "utils/AleaRandomGenerator.hpp"
#include "utils/Macro.hpp"

#include "alea/alea.h"
#include "alea/algorithms.h"

namespace deb {

AleaRandomGenerator::AleaRandomGenerator(const RNGSeed &seed)
    : state_(alea_init(reinterpret_cast<const u8 *>(seed.data()),
                       ALEA_ALGORITHM_SHAKE256)) {
    deb_assert(state_ != nullptr, "Failed to initialize Alea RNG");
}

AleaRandomGenerator::~AleaRandomGenerator() {
    if (state_) {
        alea_free(state_);
    }
}

void AleaRandomGenerator::getRandomUint64Array(u64 *dst, size_t len) {
    alea_get_random_uint64_array(state_, dst, len);
}

void AleaRandomGenerator::getRandomUint64ArrayInRange(u64 *dst, size_t len,
                                                      u64 range) {
    alea_get_random_uint64_array_in_range(state_, dst, len, range);
}

void AleaRandomGenerator::sampleGaussianInt64Array(i64 *dst, size_t len,
                                                   double stdev) {
    alea_sample_gaussian_int64_array(state_, dst, len, stdev);
}

void AleaRandomGenerator::sampleHwtInt8Array(i8 *dst, size_t len, int hwt) {
    alea_sample_hwt_int8_array(state_, dst, len, hwt);
}

void AleaRandomGenerator::reseed(const u8 *seed, size_t /*seed_len*/) {
    alea_reseed(state_, seed);
}

} // namespace deb
