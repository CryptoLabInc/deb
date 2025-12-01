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
#include "Context.hpp"
#include "utils/FFT.hpp"
#include "utils/ModArith.hpp"

#include "alea/alea.h"

#include <cstring>
#include <optional>
#include <vector>

namespace deb {

/**
 * @brief Generates an encryption key and switching keys for CKKS presets.
 */
class KeyGenerator {
public:
    /**
     * @brief Builds a key generator for a preset when no secret key is
     * provided.
     * @param preset Target preset whose parameters drive key sizes.
     * @param seeds Optional deterministic RNG seed material.
     */
    explicit KeyGenerator(const Preset preset,
                          std::optional<const RNGSeed> seeds = std::nullopt);
    /**
     * @brief Builds a key generator around an existing secret key.
     * @param sk Secret key that serves as the default source of secret data.
     * @param seeds Optional deterministic RNG seed material used when new
     * samples are required.
     */
    explicit KeyGenerator(const SecretKey &sk,
                          std::optional<const RNGSeed> seeds = std::nullopt);

    KeyGenerator(const KeyGenerator &) = delete;
    ~KeyGenerator() = default;

    /**
     * @brief Generates a switching key that maps one polynomial basis to
     * another.
     * @param from Polynomial representation of the source secret key.
     * @param to Polynomial representation of the destination secret key.
     * @param ax Polynomial components in the ax-part of the output switch key.
     * @param bx Polynomial components in the bx-part of the output switch key.
     * @param ax_size Optional size hint for the ax buffer.
     * @param bx_size Optional size hint for the bx buffer.
     */
    void genSwitchingKey(const Polynomial *from, const Polynomial *to,
                         Polynomial *ax, Polynomial *bx, const Size ax_size = 0,
                         const Size bx_size = 0) const;

    /**
     * @brief Generates a fresh encryption key.
     * @param sk Optional override secret key; if empty the internally managed
     * key is used.
     * @return Newly created encryption key.
     */
    SwitchKey genEncKey(std::optional<SecretKey> sk = std::nullopt) const;
    /**
     * @brief Generates an encryption key in-place.
     * @param enckey Output storage for encryption key.
     * @param sk Optional override secret key.
     */
    void genEncKeyInplace(SwitchKey &enckey,
                          std::optional<SecretKey> sk = std::nullopt) const;
    /**
     * @brief Generates a multiplication key used for ciphertext-ciphertext
     * products.
     * @param sk Optional override secret key.
     * @return Switching key specialized for multiplication.
     */
    SwitchKey genMultKey(std::optional<SecretKey> sk = std::nullopt) const;
    /**
     * @brief Generates a multiplication key in-place.
     * @param mulkey Output storage for multiplication key.
     * @param sk Optional override secret key.
     */
    void genMultKeyInplace(SwitchKey &mulkey,
                           std::optional<SecretKey> sk = std::nullopt) const;
    /**
     * @brief Generates a conjugation key for complex conjugate operations.
     * @param sk Optional override secret key.
     * @return Switching key for conjugation.
     */
    SwitchKey genConjKey(std::optional<SecretKey> sk = std::nullopt) const;
    /**
     * @brief Generates a conjugation key in-place.
     * @param conjkey Output storage for conjugation key.
     * @param sk Optional override secret key.
     */
    void genConjKeyInplace(SwitchKey &conjkey,
                           std::optional<SecretKey> sk = std::nullopt) const;
    /**
     * @brief Generates a left rotation key for slot rotations.
     * @param rot Rotation step expressed in slots.
     * @param sk Optional override secret key.
     * @return Switching key bound to the requested rotation.
     */
    SwitchKey genLeftRotKey(const Size rot,
                            std::optional<SecretKey> sk = std::nullopt) const;
    /**
     * @brief Generates a left rotation key and writes it to an existing
     * structure.
     * @param rot Rotation step expressed in slots.
     * @param rotkey Output storage for left rotation key.
     * @param sk Optional override secret key.
     */
    void genLeftRotKeyInplace(const Size rot, SwitchKey &rotkey,
                              std::optional<SecretKey> sk = std::nullopt) const;
    /**
     * @brief Generates a right rotation key for slot rotations.
     * @param rot Rotation step expressed in slots.
     * @param sk Optional override secret key.
     * @return Switching key bound to the requested rotation.
     */
    SwitchKey genRightRotKey(const Size rot,
                             std::optional<SecretKey> sk = std::nullopt) const;
    /**
     * @brief Generates a right rotation key into an existing object.
     * @param rot Rotation step expressed in slots.
     * @param rotkey Output storage for right rotation key.
     * @param sk Optional override secret key.
     */
    void
    genRightRotKeyInplace(const Size rot, SwitchKey &rotkey,
                          std::optional<SecretKey> sk = std::nullopt) const;
    /**
     * @brief Generates an automorphism key identified by the exponent sig.
     * @param sig The power index of the automorphism.
     * @param sk Optional override secret key.
     * @return Switching key that realizes the automorphism.
     */
    SwitchKey genAutoKey(const Size sig,
                         std::optional<SecretKey> sk = std::nullopt) const;
    /**
     * @brief Generates an automorphism key into an existing object.
     * @param sig Automorphism identifier.
     * @param autokey Output storage for automorphism key.
     * @param sk Optional override secret key.
     */
    void genAutoKeyInplace(const Size sig, SwitchKey &autokey,
                           std::optional<SecretKey> sk = std::nullopt) const;

    /**
     * @brief Generates a composition switch key from an input secret key.
     * @param sk_from Source secret key to be composed into the managed key.
     * @param sk Optional target secret key override.
     * @return Switching key that composes @p sk_from into @p sk.
     */
    SwitchKey genComposeKey(const SecretKey &sk_from,
                            std::optional<SecretKey> sk = std::nullopt) const;
    /**
     * @brief @overload
     * @param coeffs Coefficient vector that describes the source secret key.
     */
    SwitchKey genComposeKey(const std::vector<i8> coeffs,
                            std::optional<SecretKey> sk = std::nullopt) const;
    /**
     * @brief @overload
     * @param coeffs Pointer to coefficient data.
     * @param size Number of coefficients provided.
     */
    SwitchKey genComposeKey(const i8 *coeffs, Size size,
                            std::optional<SecretKey> sk = std::nullopt) const;
    /**
     * @brief Generates a composition key directly into an existing object.
     * @param sk_from Source secret key to be composed.
     * @param composekey Output storage for composition key.
     * @param sk Optional target secret key override.
     */
    void genComposeKeyInplace(const SecretKey &sk_from, SwitchKey &composekey,
                              std::optional<SecretKey> sk = std::nullopt) const;
    /**
     * @brief @overload
     * @param coeffs Coefficient vector describing the source secret key.
     * @param composekey Output storage for composition key.
     * @param sk Optional target secret key override.
     */
    void genComposeKeyInplace(const std::vector<i8> coeffs,
                              SwitchKey &composekey,
                              std::optional<SecretKey> sk = std::nullopt) const;
    /**
     * @brief @overload
     * @param coeffs Pointer to coefficient data.
     * @param size Number of coefficients supplied.
     * @param composekey Output storage for composition key.
     * @param sk Optional target secret key override.
     */
    void genComposeKeyInplace(const i8 *coeffs, Size size,
                              SwitchKey &composekey,
                              std::optional<SecretKey> sk = std::nullopt) const;

    /**
     * @brief Generates a decomposition key that maps to the provided target
     * secret key.
     * @param sk_to Destination secret key.
     * @param sk Optional source secret key override.
     * @return Switching key used for decomposition.
     */
    SwitchKey genDecomposeKey(const SecretKey &sk_to,
                              std::optional<SecretKey> sk = std::nullopt) const;
    /**
     * @brief @overload
     * @param coeffs Coefficient vector describing the destination secret key.
     */
    SwitchKey genDecomposeKey(const std::vector<i8> coeffs,
                              std::optional<SecretKey> sk = std::nullopt) const;
    /**
     * @brief @overload
     * @param coeffs Pointer to coefficient data.
     * @param coeffs_size Number of coefficients supplied.
     */
    SwitchKey genDecomposeKey(const i8 *coeffs, Size coeffs_size,
                              std::optional<SecretKey> sk = std::nullopt) const;
    /**
     * @brief Fills an existing switch key with decomposition data targeted at
     * @p sk_to.
     * @param sk_to Destination secret key.
     * @param decompkey Output storage for decomposition key.
     * @param sk Optional source secret key override.
     */
    void
    genDecomposeKeyInplace(const SecretKey &sk_to, SwitchKey &decompkey,
                           std::optional<SecretKey> sk = std::nullopt) const;
    /**
     * @brief @overload
     * @param coeffs Destination secret key coefficients.
     * @param decompkey Output storage for decomposition key.
     * @param sk Optional source secret key override.
     */
    void
    genDecomposeKeyInplace(const std::vector<i8> coeffs, SwitchKey &decompkey,
                           std::optional<SecretKey> sk = std::nullopt) const;
    /**
     * @brief @overload
     * @param coeffs Destination secret key coefficients buffer.
     * @param coeffs_size Number of coefficients supplied.
     * @param decompkey Output storage for decomposition key.
     * @param sk Optional source secret key override.
     */
    void
    genDecomposeKeyInplace(const i8 *coeffs, Size coeffs_size,
                           SwitchKey &decompkey,
                           std::optional<SecretKey> sk = std::nullopt) const;

    /**
     * @brief Generates a decomposition key using preset-specific parameters.
     * @param preset_swk Preset that controls switching key layout.
     * @param sk_to Destination secret key.
     * @param sk Optional source secret key override.
     * @return Switching key configured for @p preset_swk.
     */
    SwitchKey genDecomposeKey(const Preset preset_swk, const SecretKey &sk_to,
                              std::optional<SecretKey> sk = std::nullopt) const;
    /**
     * @brief @overload
     * @param coeffs Destination secret key coefficients.
     */
    SwitchKey genDecomposeKey(const Preset preset_swk,
                              const std::vector<i8> coeffs,
                              std::optional<SecretKey> sk = std::nullopt) const;
    /**
     * @brief @overload
     * @param coeffs Pointer to coefficient data.
     * @param coeffs_size Number of coefficients supplied.
     */
    SwitchKey genDecomposeKey(const Preset preset_swk, const i8 *coeffs,
                              Size coeffs_size,
                              std::optional<SecretKey> sk = std::nullopt) const;
    /**
     * @brief Fills an existing switch key using preset-specific parameters.
     * @param preset_swk Preset that controls the generated layout.
     * @param sk_to Destination secret key.
     * @param decompkey Output storage for decomposition key.
     * @param sk Optional source secret key override.
     */
    void
    genDecomposeKeyInplace(const Preset preset_swk, const SecretKey &sk_to,
                           SwitchKey &decompkey,
                           std::optional<SecretKey> sk = std::nullopt) const;
    /**
     * @brief @overload
     * @param coeffs Destination secret key coefficients.
     * @param decompkey Output storage for decomposition key.
     * @param sk Optional source secret key override.
     */
    void
    genDecomposeKeyInplace(const Preset preset_swk,
                           const std::vector<i8> coeffs, SwitchKey &decompkey,
                           std::optional<SecretKey> sk = std::nullopt) const;
    /**
     * @brief @overload
     * @param coeffs Pointer to destination secret key coefficients.
     * @param coeffs_size Number of coefficients supplied.
     * @param decompkey Output storage for decomposition key.
     * @param sk Optional source secret key override.
     */
    void
    genDecomposeKeyInplace(const Preset preset_swk, const i8 *coeffs,
                           Size coeffs_size, SwitchKey &decompkey,
                           std::optional<SecretKey> sk = std::nullopt) const;

    /**
     * @brief Generates a bundle of modulus packing keys between two secret
     * keys.
     * @param sk_from Source secret key.
     * @param sk_to Destination secret key.
     * @return Vector of switching keys implementing the mod-pack bundle.
     */
    std::vector<SwitchKey> genModPackKeyBundle(const SecretKey &sk_from,
                                               const SecretKey &sk_to) const;
    /**
     * @brief Populates an existing bundle with modulus packing keys.
     * @param sk_from Source secret key.
     * @param sk_to Destination secret key.
     * @param key_bundle Output vector to populate.
     */
    void genModPackKeyBundleInplace(const SecretKey &sk_from,
                                    const SecretKey &sk_to,
                                    std::vector<SwitchKey> &key_bundle) const;

    // For self modpack
    /**
     * @brief Generates a modulus packing key for self mod-pack operations.
     * @param pad_rank Rank padding parameter.
     * @param sk Optional override secret key.
     * @return Switching key configured for self mod-pack.
     */
    SwitchKey
    genModPackKeyBundle(const Size pad_rank,
                        std::optional<SecretKey> sk = std::nullopt) const;
    /**
     * @brief Generates a self mod-pack key in-place.
     * @param pad_rank Rank padding parameter.
     * @param modkey Output storage for mod-pack key.
     * @param sk Optional override secret key.
     */
    void genModPackKeyBundleInplace(
        const Size pad_rank, SwitchKey &modkey,
        std::optional<SecretKey> sk = std::nullopt) const;

private:
    void frobeniusMapInNTT(const Polynomial &op, const i32 pow,
                           Polynomial res) const;

    Polynomial sampleGaussian(const Size num_polyunit,
                              bool do_ntt = false) const;

    void sampleUniform(Polynomial &poly) const;
    void computeConst();

    Context context_;
    std::optional<SecretKey> sk_;
    std::shared_ptr<alea_state> as_;

    // TODO: move to Context
    std::vector<u64> p_mod_;
    std::vector<u64> hat_q_i_mod_;
    std::vector<u64> hat_q_i_inv_mod_;
    std::vector<utils::ModArith> modarith_;
    utils::FFT fft_;
};

} // namespace deb
