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
#include "utils/FFT.hpp"
#include "utils/PresetTraits.hpp"
#include "utils/RandomGenerator.hpp"

#include <cstring>
#include <optional>
#include <vector>

namespace deb {

/**
 * @brief Generates an encryption key and switching keys for CKKS presets.
 */
template <Preset P = PRESET_EMPTY>
class KeyGeneratorT : public PresetTraits<P> {
#define CV(type, var_name) using PresetTraits<P>::var_name;
    CONST_LIST
#undef CV
    using PresetTraits<P>::modarith;

public:
    /**
     * @brief Builds a key generator for a preset when no secret key is
     * provided. An external secret key must be given for key generation calls.
     * @param preset Target preset whose parameters drive key sizes.
     * @param seeds Optional deterministic RNG seed material used when new
     * samples are required.
     */
    explicit KeyGeneratorT(std::optional<const RNGSeed> seeds = std::nullopt);
    explicit KeyGeneratorT(const Preset preset,
                           std::optional<const RNGSeed> seeds = std::nullopt);
    /**
     * @brief Builds a key generator with a custom random generator.
     * @param preset Target preset whose parameters drive key sizes.
     * @param rng Custom random generator instance.
     */
    explicit KeyGeneratorT(const Preset preset,
                           std::shared_ptr<RandomGenerator> rng);

    KeyGeneratorT(const KeyGeneratorT &) = delete;
    ~KeyGeneratorT() = default;

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
     * @brief Generates an encryption key.
     * @param sk Secret key to generate public key.
     * @return Newly created encryption key.
     */
    SwitchKey genEncKey(const SecretKey &sk) const;
    /**
     * @brief Generates an encryption key directly into an existing object.
     * @param enckey Output storage for encryption key.
     * @param sk Secret key to generate public key.
     */
    void genEncKeyInplace(SwitchKey &enckey, const SecretKey &sk) const;
    /**
     * @brief Generates a multiplication key used for ciphertext-ciphertext
     * products.
     * @param sk Secret key to generate public key.
     * @return Multiplication key.
     */
    SwitchKey genMultKey(const SecretKey &sk) const;
    /**
     * @brief Generates a multiplication key directly into an existing object.
     * @param mulkey Output storage for multiplication key.
     * @param sk Secret key to generate public key.
     */
    void genMultKeyInplace(SwitchKey &mulkey, const SecretKey &sk) const;
    /**
     * @brief Generates a conjugation key for complex conjugate operations.
     * @param sk Secret key to generate public key.
     * @return Conjugation key.
     */
    SwitchKey genConjKey(const SecretKey &sk) const;
    /**
     * @brief Generates a conjugation key directly into an existing object.
     * @param conjkey Output storage for conjugation key.
     * @param sk Secret key to generate public key.
     */
    void genConjKeyInplace(SwitchKey &conjkey, const SecretKey &sk) const;
    /**
     * @brief Generates a left rotation key for specific rotate operation.
     * @param rot Rotation index.
     * @param sk Secret key to generate public key.
     * @return Left rotation key of rotation index @p rot.
     */
    SwitchKey genLeftRotKey(const Size rot, const SecretKey &sk) const;
    /**
     * @brief Generates a left rotation key directly into an existing object.
     * @param rot Rotation index.
     * @param rotkey Output storage for left rotation key.
     * @param sk Secret key to generate public key.
     */
    void genLeftRotKeyInplace(const Size rot, SwitchKey &rotkey,
                              const SecretKey &sk) const;
    /**
     * @brief Generates a right rotation key for specific rotate operation.
     * @param rot Rotation index.
     * @param sk Secret key to generate public key.
     * @return Right rotation key of rotation index @p rot.
     */
    SwitchKey genRightRotKey(const Size rot, const SecretKey &sk) const;
    /**
     * @brief Generates a right rotation key directly into an existing object.
     * @param rot Rotation index.
     * @param rotkey Output storage for right rotation key.
     * @param sk Secret key to generate public key.
     */
    void genRightRotKeyInplace(const Size rot, SwitchKey &rotkey,
                               const SecretKey &sk) const;
    /**
     * @brief Generates an automorphism key identified by the exponent sig.
     * @param sig The power index of the automorphism.
     * @param sk Secret key to generate public key.
     * @return Switching key that realizes the automorphism.
     */
    SwitchKey genAutoKey(const Size sig, const SecretKey &sk) const;
    /**
     * @brief Generates an automorphism key directly into an existing object.
     * @param sig Automorphism identifier.
     * @param autokey Output storage for automorphism key.
     * @param sk Secret key to generate public key.
     */
    void genAutoKeyInplace(const Size sig, SwitchKey &autokey,
                           const SecretKey &sk) const;

    /**
     * @brief Generates a composition switch key from an input secret key @p
     * sk_from.
     * @param sk_from Source secret key to be composed into the managed key.
     * @param sk Optional target secret key override.
     * @return Composition key from @p sk_from.
     */
    SwitchKey genComposeKey(const SecretKey &sk_from,
                            const SecretKey &sk) const;
    /**
     * @brief @overload
     * @param coeffs Coefficient vector that describes the source secret key.
     * @param sk Optional target secret key override.
     * @return Composition key from the secret key from @p coeffs.
     */
    SwitchKey genComposeKey(const std::vector<i8> coeffs,
                            const SecretKey &sk) const;
    /**
     * @brief @overload
     * @param coeffs Pointer to coefficient data.
     * @param size Number of coefficients provided.
     * @param sk Optional target secret key override.
     * @return Composition key from the secret key from @p coeffs.
     */
    SwitchKey genComposeKey(const i8 *coeffs, Size size,
                            const SecretKey &sk) const;
    /**
     * @brief Generates a composition key directly into an existing object.
     * @param sk_from Source secret key to be composed.
     * @param composekey Output storage for composition key.
     * @param sk Optional target secret key override.
     */
    void genComposeKeyInplace(const SecretKey &sk_from, SwitchKey &composekey,
                              const SecretKey &sk) const;
    /**
     * @brief @overload
     * @param coeffs Coefficient vector describing the source secret key.
     * @param composekey Output storage for composition key.
     * @param sk Optional target secret key override.
     */
    void genComposeKeyInplace(const std::vector<i8> coeffs,
                              SwitchKey &composekey, const SecretKey &sk) const;
    /**
     * @brief @overload
     * @param coeffs Pointer to coefficient data.
     * @param size Number of coefficients supplied.
     * @param composekey Output storage for composition key.
     * @param sk Optional target secret key override.
     */
    void genComposeKeyInplace(const i8 *coeffs, Size size,
                              SwitchKey &composekey, const SecretKey &sk) const;

    /**
     * @brief Generates a decomposition key that maps to the provided target
     * secret key @p sk_to.
     * @param sk_to Destination secret key.
     * @param sk Optional source secret key override.
     * @return Decomposition key maps to @p sk_to.
     */
    SwitchKey genDecomposeKey(const SecretKey &sk_to,
                              const SecretKey &sk) const;
    /**
     * @brief @overload
     * @param coeffs Coefficient vector describing the destination secret key.
     * @param sk Optional source secret key override.
     * @return Decomposition key maps to the secret key from @p coeffs.
     */
    SwitchKey genDecomposeKey(const std::vector<i8> coeffs,
                              const SecretKey &sk) const;
    /**
     * @brief @overload
     * @param coeffs Pointer to coefficient data.
     * @param coeffs_size Number of coefficients supplied.
     * @param sk Optional source secret key override.
     * @return Decomposition key maps to the secret key from @p coeffs.
     */
    SwitchKey genDecomposeKey(const i8 *coeffs, Size coeffs_size,
                              const SecretKey &sk) const;
    /**
     * @brief Generates a decomposition key directly into an existing object.
     * @param sk_to Destination secret key.
     * @param decompkey Output storage for decomposition key.
     * @param sk Optional source secret key override.
     */
    void genDecomposeKeyInplace(const SecretKey &sk_to, SwitchKey &decompkey,
                                const SecretKey &sk) const;
    /**
     * @brief @overload
     * @param coeffs Destination secret key coefficients.
     * @param decompkey Output storage for decomposition key.
     * @param sk Optional source secret key override.
     */
    void genDecomposeKeyInplace(const std::vector<i8> coeffs,
                                SwitchKey &decompkey,
                                const SecretKey &sk) const;
    /**
     * @brief @overload
     * @param coeffs Destination secret key coefficients buffer.
     * @param coeffs_size Number of coefficients supplied.
     * @param decompkey Output storage for decomposition key.
     * @param sk Optional source secret key override.
     */
    void genDecomposeKeyInplace(const i8 *coeffs, Size coeffs_size,
                                SwitchKey &decompkey,
                                const SecretKey &sk) const;

    /**
     * @brief Generates a decomposition key using preset-specific parameters.
     * @param preset_swk Preset that controls switching key layout.
     * @param sk_to Destination secret key.
     * @param sk Optional source secret key override.
     * @return Decomposition key configured for @p preset_swk.
     */
    SwitchKey genDecomposeKey(const Preset preset_swk, const SecretKey &sk_to,
                              const SecretKey &sk) const;
    /**
     * @brief @overload
     * @param preset_swk Preset that controls switching key layout.
     * @param coeffs Destination secret key coefficients.
     * @param sk Optional source secret key override.
     * @return Decomposition key configured for @p preset_swk.
     */
    SwitchKey genDecomposeKey(const Preset preset_swk,
                              const std::vector<i8> coeffs,
                              const SecretKey &sk) const;
    /**
     * @brief @overload
     * @param preset_swk Preset that controls switching key layout.
     * @param coeffs Pointer to coefficient data.
     * @param coeffs_size Number of coefficients supplied.
     * @param sk Optional source secret key override.
     * @return Decomposition key configured for @p preset_swk.
     */
    SwitchKey genDecomposeKey(const Preset preset_swk, const i8 *coeffs,
                              Size coeffs_size, const SecretKey &sk) const;
    /**
     * @brief Generate a decomposition key directly into an existing object
     * using preset-specific parameters.
     * @param preset_swk Preset that controls the generated layout.
     * @param sk_to Destination secret key.
     * @param decompkey Output storage for decomposition key.
     * @param sk Optional source secret key override.
     */
    void genDecomposeKeyInplace(const Preset preset_swk, const SecretKey &sk_to,
                                SwitchKey &decompkey,
                                const SecretKey &sk) const;
    /**
     * @brief @overload
     * @param preset_swk Preset that controls the generated layout.
     * @param coeffs Destination secret key coefficients.
     * @param decompkey Output storage for decomposition key.
     * @param sk Optional source secret key override.
     */
    void genDecomposeKeyInplace(const Preset preset_swk,
                                const std::vector<i8> coeffs,
                                SwitchKey &decompkey,
                                const SecretKey &sk) const;
    /**
     * @brief @overload
     * @param preset_swk Preset that controls the generated layout.
     * @param coeffs Pointer to destination secret key coefficients.
     * @param coeffs_size Number of coefficients supplied.
     * @param decompkey Output storage for decomposition key.
     * @param sk Optional source secret key override.
     */
    void genDecomposeKeyInplace(const Preset preset_swk, const i8 *coeffs,
                                Size coeffs_size, SwitchKey &decompkey,
                                const SecretKey &sk) const;

    /**
     * @brief Generates a bundle of modulus packing keys between two secret
     * keys.
     * @param sk_from Source secret key.
     * @param sk_to Destination secret key.
     * @return Vector of modpack keys from @p sk_from to @p sk_to.
     */
    std::vector<SwitchKey> genModPackKeyBundle(const SecretKey &sk_from,
                                               const SecretKey &sk_to) const;
    /**
     * @brief Generate a bundle of modulus packing keys directly into an
     * existing object.
     * @param sk_from Source secret key.
     * @param sk_to Destination secret key.
     * @param key_bundle Output storage for modpack key bundle.
     */
    void genModPackKeyBundleInplace(const SecretKey &sk_from,
                                    const SecretKey &sk_to,
                                    std::vector<SwitchKey> &key_bundle) const;

    // For self modpack
    /**
     * @brief Generates a modulus packing key for self mod-pack operations.
     * @param pad_rank Rank parameter, assumed to be padded power of two.
     * @param sk Secret key to generate public key.
     * @return Modpack keys with @p pad_rank.
     */
    SwitchKey genModPackKeyBundle(const Size pad_rank,
                                  const SecretKey &sk) const;
    /**
     * @brief Generates a self mod-pack key in-place.
     * @param pad_rank Rank parameter, assumed to be padded power of two.
     * @param modkey Output storage for mod-pack key.
     * @param sk Secret key to generate public key.
     */
    void genModPackKeyBundleInplace(const Size pad_rank, SwitchKey &modkey,
                                    const SecretKey &sk) const;

private:
    void frobeniusMapInNTT(const Polynomial &op, const i32 pow,
                           Polynomial res) const;

    Polynomial sampleGaussian(const Size num_polyunit,
                              bool do_ntt = false) const;

    void sampleUniform(Polynomial &poly) const;
    void computeConst();

    std::shared_ptr<RandomGenerator> rng_;

    // TODO: move to Context
    std::vector<u64> p_mod_;
    std::vector<u64> hat_q_i_mod_;
    std::vector<u64> hat_q_i_inv_mod_;
    utils::FFT fft_;
};

using KeyGenerator = KeyGeneratorT<>;

#define X(preset) extern template class KeyGeneratorT<PRESET_##preset>;
PRESET_LIST_WITH_EMPTY
#undef X
} // namespace deb
