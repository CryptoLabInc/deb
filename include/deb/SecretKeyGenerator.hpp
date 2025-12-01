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

#include "CKKSTypes.hpp"
#include "Constant.hpp"
#include "Context.hpp"
#include "SeedGenerator.hpp"
#include "utils/NTT.hpp"

#include "DebFBType.h"
#include "alea/alea.h"
#include "alea/algorithms.h"

#include <cstring>
#include <fstream>
#include <memory>
#include <optional>
#include <random>

namespace deb {

// template <typename Evaluator>
/**
 * @brief Generates secret keys and secret coefficients for CKKS presets.
 */
class SecretKeyGenerator {
public:
    /**
     * @brief Builds a generator bound to the supplied preset.
     * @param preset Target preset.
     */
    SecretKeyGenerator(const Preset preset);

    /**
     * @brief Generates a new secret key.
     * @param seeds Optional deterministic RNG seeds.
     * @return Fresh secret key.
     */
    SecretKey genSecretKey(std::optional<const RNGSeed> seeds = std::nullopt);
    /**
     * @brief Generates a secret key into the provided object.
     * @param sk Output storage for secret key.
     * @param seeds Optional deterministic seed override.
     */
    void genSecretKeyInplace(SecretKey &sk,
                             std::optional<const RNGSeed> seeds = std::nullopt);
    /**
     * @brief Builds a secret key from explicit coefficient data.
     * @param coeffs Pointer to coefficient array sized per preset degree.
     * @return Secret key containing the provided coefficients.
     */
    SecretKey genSecretKeyFromCoeff(const i8 *coeffs);
    /**
     * @brief Writes coefficient data into an existing secret key.
     * @param sk Output storage for secret key.
     * @param coeffs Pointer to coefficient array sized per preset degree.
     */
    void genSecretKeyFromCoeffInplace(SecretKey &sk, const i8 *coeffs);

    /**
     * @brief Generates secret-key coefficients deterministically.
     * @param preset Target preset.
     * @param seed Deterministic RNG seed.
     * @return Newly allocated coefficient buffer.
     */
    static i8 *GenCoeff(const Preset preset, const RNGSeed seed);
    /**
     * @brief Deterministically fills an existing coefficient buffer.
     * @param preset Target preset.
     * @param coeffs Output storage for coefficients.
     * @param seed Optional deterministic seed override.
     * @return Seed actually used, which may be derived internally.
     */
    static RNGSeed
    GenCoeffInplace(const Preset preset, i8 *coeffs,
                    std::optional<const RNGSeed> seed = std::nullopt);

    /**
     * @brief Computes the canonical embedding of coefficients into a secret
     * key container.
     * @param preset Target preset.
     * @param coeffs Pointer to coefficient data.
     * @param level Optional modulus level limitation.
     * @return Secret key containing the embedded representation.
     */
    static SecretKey ComputeEmbedding(const Preset preset, const i8 *coeffs,
                                      std::optional<Size> level = std::nullopt);
    /**
     * @brief Writes an embedding into an existing secret key.
     * @param sk Output storage for secret key.
     * @param coeffs Source coefficient data.
     */
    static void ComputeEmbeddingInplace(SecretKey &sk, const i8 *coeffs);

    /**
     * @brief Convenience wrapper that constructs a generator and produces a
     * secret key.
     * @param preset Target preset.
     * @param seeds Optional deterministic seed.
     * @return Newly generated secret key.
     */
    static SecretKey
    GenSecretKey(const Preset preset,
                 std::optional<const RNGSeed> seeds = std::nullopt);
    /**
     * @brief Generates a secret key in-place without instantiating a separate
     * generator.
     * @param sk Output storage for secret key.
     * @param seeds Optional deterministic seed.
     */
    static void
    GenSecretKeyInplace(SecretKey &sk,
                        std::optional<const RNGSeed> seeds = std::nullopt);

    /**
     * @brief Builds a secret key from explicit coefficients without creating
     * an instance.
     * @param preset Target preset.
     * @param coeffs Pointer to coefficient data.
     * @return Secret key containing the provided coefficients.
     */
    static SecretKey GenSecretKeyFromCoeff(const Preset preset,
                                           const i8 *coeffs);
    /**
     * @brief Writes coefficient data into an existing secret key without
     * instantiating a generator.
     * @param sk Output storage for secret key.
     * @param coeffs Pointer to coefficient data.
     */
    static void GenSecretKeyFromCoeffInplace(SecretKey &sk, const i8 *coeffs);

private:
    Preset preset_;
};

/**
 * @brief Ensures a secret key has fully allocated polynomial representations.
 * @param sk Secret key to complete.
 * @param level Optional modulus level restriction.
 */
void completeSecretKey(SecretKey &sk, std::optional<Size> level = std::nullopt);

} // namespace deb
