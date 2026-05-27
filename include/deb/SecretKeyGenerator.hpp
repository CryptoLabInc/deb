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

#include "CKKSTypes.hpp"
#include "utils/Constant.hpp"
#include "utils/NTT.hpp"
#include "utils/RandomGenerator.hpp"

#include <cstring>
#include <fstream>
#include <memory>
#include <optional>
#include <random>

namespace deb {

/**
 * @brief Generates secret keys and secret coefficients for CKKS presets.
 *
 * @tparam U Coefficient word type (u32 or u64, default u64).
 */
template <typename U = u64> class SecretKeyGeneratorT {
public:
    /**
     * @brief Builds a generator bound to the supplied preset.
     * @param preset Target preset.
     */
    SecretKeyGeneratorT(const Preset preset);

    /**
     * @brief Generates a new secret key.
     * @param seeds Optional deterministic RNG seeds.
     * @param ntt_type NTT type used for the polynomial embedding (default:
     * negacyclic, matching standard CKKS).  Pass NTTType::CYCLIC for
     * real-HEAAN mode.
     * @return Fresh secret key.
     */
    SecretKeyT<U>
    genSecretKey(std::optional<const RNGSeed> seeds = std::nullopt,
                 utils::NTTType ntt_type = utils::NTTType::NEGACYCLIC);
    /**
     * @brief Generates a secret key into the provided object.
     * @param sk Output storage for secret key.
     * @param seeds Optional deterministic seed override.
     * @param ntt_type NTT type for the polynomial embedding.
     */
    void
    genSecretKeyInplace(SecretKeyT<U> &sk,
                        std::optional<const RNGSeed> seeds = std::nullopt,
                        utils::NTTType ntt_type = utils::NTTType::NEGACYCLIC);
    /**
     * @brief Builds a secret key from explicit coefficient data.
     * @param coeffs Pointer to coefficient array sized per preset degree.
     * @param ntt_type NTT type for the polynomial embedding.
     * @return Secret key containing the provided coefficients.
     */
    SecretKeyT<U>
    genSecretKeyFromCoeff(const i8 *coeffs,
                          utils::NTTType ntt_type = utils::NTTType::NEGACYCLIC);
    /**
     * @brief Writes coefficient data into an existing secret key.
     * @param sk Output storage for secret key.
     * @param coeffs Pointer to coefficient array sized per preset degree.
     * @param ntt_type NTT type for the polynomial embedding.
     */
    void genSecretKeyFromCoeffInplace(
        SecretKeyT<U> &sk, const i8 *coeffs,
        utils::NTTType ntt_type = utils::NTTType::NEGACYCLIC);

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
     * @param ntt_type NTT type for the polynomial embedding.
     * @return Secret key containing the embedded representation.
     */
    static SecretKeyT<U>
    ComputeEmbedding(const Preset preset, const i8 *coeffs,
                     std::optional<Size> level = std::nullopt,
                     utils::NTTType ntt_type = utils::NTTType::NEGACYCLIC);
    /**
     * @brief Writes an embedding into an existing secret key.
     * @param sk Output storage for secret key.
     * @param coeffs Source coefficient data.
     * @param ntt_type NTT type for the polynomial embedding.
     */
    static void ComputeEmbeddingInplace(
        SecretKeyT<U> &sk, const i8 *coeffs,
        utils::NTTType ntt_type = utils::NTTType::NEGACYCLIC);

    /**
     * @brief Convenience wrapper that constructs a generator and produces a
     * secret key.
     * @param preset Target preset.
     * @param seeds Optional deterministic seed.
     * @param ntt_type NTT type for the polynomial embedding.
     * @return Newly generated secret key.
     */
    static SecretKeyT<U>
    GenSecretKey(const Preset preset,
                 std::optional<const RNGSeed> seeds = std::nullopt,
                 utils::NTTType ntt_type = utils::NTTType::NEGACYCLIC);
    /**
     * @brief Generates a secret key in-place without instantiating a separate
     * generator.
     * @param sk Output storage for secret key.
     * @param seeds Optional deterministic seed.
     * @param ntt_type NTT type for the polynomial embedding.
     */
    static void
    GenSecretKeyInplace(SecretKeyT<U> &sk,
                        std::optional<const RNGSeed> seeds = std::nullopt,
                        utils::NTTType ntt_type = utils::NTTType::NEGACYCLIC);

    /**
     * @brief Builds a secret key from explicit coefficients without creating
     * an instance.
     * @param preset Target preset.
     * @param coeffs Pointer to coefficient data.
     * @param ntt_type NTT type for the polynomial embedding.
     * @return Secret key containing the provided coefficients.
     */
    static SecretKeyT<U>
    GenSecretKeyFromCoeff(const Preset preset, const i8 *coeffs,
                          utils::NTTType ntt_type = utils::NTTType::NEGACYCLIC);
    /**
     * @brief Writes coefficient data into an existing secret key without
     * instantiating a generator.
     * @param sk Output storage for secret key.
     * @param coeffs Pointer to coefficient data.
     * @param ntt_type NTT type for the polynomial embedding.
     */
    static void GenSecretKeyFromCoeffInplace(
        SecretKeyT<U> &sk, const i8 *coeffs,
        utils::NTTType ntt_type = utils::NTTType::NEGACYCLIC);

private:
    const Preset preset_;
};

/**
 * @brief Ensures a secret key has fully allocated polynomial representations.
 * @param sk Secret key to complete.
 * @param level Optional modulus level restriction.
 * @param ntt_type NTT type for the polynomial embedding.
 */
template <typename U = u64>
void completeSecretKey(SecretKeyT<U> &sk,
                       std::optional<Size> level = std::nullopt,
                       utils::NTTType ntt_type = utils::NTTType::NEGACYCLIC);

// Explicit instantiation declarations
#ifdef DEB_U64
using SecretKeyGenerator = SecretKeyGeneratorT<u64>;
extern template class SecretKeyGeneratorT<u64>;
extern template void completeSecretKey<u64>(SecretKey &, std::optional<Size>,
                                            utils::NTTType);
#endif
#ifdef DEB_U32
using SecretKeyGenerator32 = SecretKeyGeneratorT<u32>;
extern template class SecretKeyGeneratorT<u32>;
extern template void completeSecretKey<u32>(SecretKey32 &, std::optional<Size>,
                                            utils::NTTType);

#endif

} // namespace deb
