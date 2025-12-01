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

#pragma once

#include "Context.hpp"

#include "alea/alea.h"
#include "alea/algorithms.h"

#include <array>
#include <optional>

namespace deb {

/**
 * @brief Number of 64-bit words in a CKKS RNG seed.
 */
constexpr size_t DEB_U64_SEED_SIZE = ALEA_SEED_SIZE_SHAKE256 / sizeof(u64);
/**
 * @brief Deterministic seed material shared across RNG utilities.
 */
using RNGSeed = std::array<u64, DEB_U64_SEED_SIZE>;

/**
 * @brief Converts the library seed format to ALEA's byte-oriented seed.
 * @param seed Source seed material.
 * @return Pointer suitable for ALEA APIs.
 */
const u8 *to_alea_seed(const RNGSeed &seed);

/**
 * @brief Singleton wrapper over ALEA to provide deterministic RNG streams.
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
     * @brief Internal helper that produces a new seed from the ALEA state.
     */
    RNGSeed genSeed();

    std::unique_ptr<alea_state, decltype(&alea_free)> as_;
};
} // namespace deb
