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
#include <optional>

namespace deb {

/**
 * @brief Singleton wrapper over RandomGenerator to provide deterministic RNG
 * streams.
 */
class SeedGenerator {
public:
    ~SeedGenerator() = default;
    SeedGenerator(const SeedGenerator &) = delete;
    SeedGenerator &operator=(const SeedGenerator &) = delete;

    /**
     * @brief Accesses the singleton, optionally reseeding it.
     * @param seeds Optional deterministic seed.
     * @return Reference to the singleton instance.
     */
    static SeedGenerator &
    GetInstance(std::optional<const RNGSeed> seeds = std::nullopt);

    /**
     * @brief Reinitializes the underlying RNG with the provided seed.
     * @param seeds Optional deterministic seed; when empty a random seed is
     * chosen.
     */
    static void Reseed(const std::optional<const RNGSeed> &seeds);
    /**
     * @brief Generates a new random seed suitable for deterministic APIs.
     * @return Fresh RNG seed.
     */
    static RNGSeed Gen();

private:
    SeedGenerator(std::optional<const RNGSeed> seeds);

    /**
     * @brief Internal helper that produces a new seed from the RNG state.
     */
    RNGSeed genSeed();

    std::shared_ptr<RandomGenerator> rng_;
};
} // namespace deb
