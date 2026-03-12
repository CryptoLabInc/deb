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

#include "utils/RandomGenerator.hpp"

#include <memory>

namespace deb {

class AleaRandomGenerator : public RandomGenerator {
public:
    explicit AleaRandomGenerator(const RNGSeed &seed);
    ~AleaRandomGenerator() override;

    AleaRandomGenerator(const AleaRandomGenerator &) = delete;
    AleaRandomGenerator &operator=(const AleaRandomGenerator &) = delete;

    void getRandomUint64Array(u64 *dst, size_t len) override;
    void getRandomUint64ArrayInRange(u64 *dst, size_t len, u64 range) override;

    void sampleGaussianInt64Array(i64 *dst, size_t len, double stdev) override;
    void sampleHwtInt8Array(i8 *dst, size_t len, int hwt) override;

    void reseed(const u8 *seed, size_t seed_len) override;

private:
    void *state_;
};

} // namespace deb
