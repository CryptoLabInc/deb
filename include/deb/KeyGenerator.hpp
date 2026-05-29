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
#include "utils/NTT.hpp"
#include "utils/PresetTraits.hpp"
#include "utils/RandomGenerator.hpp"

#include <cstring>
#include <optional>
#include <vector>

namespace deb {

/**
 * @brief Generates an encryption key and switching keys for CKKS presets.
 */
template <Preset P = PRESET_EMPTY, typename U = u64>
class KeyGeneratorT : public PresetTraits<P, U> {
#define CV(type, var_name) using PresetTraits<P, U>::var_name;
    CONST_LIST
#undef CV
    using PresetTraits<P, U>::modarith;

public:
    /**
     * @brief Builds a key generator for a preset when no secret key is
     * provided. An external secret key must be given for key generation calls.
     * @param target_preset Target preset whose parameters drive key sizes.
     * @param seeds Optional deterministic RNG seed material used when new
     * samples are required.
     */
    explicit KeyGeneratorT(std::optional<const RNGSeed> seeds = std::nullopt);
    explicit KeyGeneratorT(const Preset target_preset,
                           std::optional<const RNGSeed> seeds = std::nullopt);
    /**
     * @brief Builds a key generator with a custom random generator.
     * @param target_preset Target preset whose parameters drive key sizes.
     * @param rng Custom random generator instance.
     */
    explicit KeyGeneratorT(const Preset target_preset,
                           std::shared_ptr<RandomGenerator> rng);

    KeyGeneratorT(const KeyGeneratorT &) = delete;
    ~KeyGeneratorT() = default;

    void addNTTType(const utils::NTTType ntt_type);
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
    void genSwitchingKey(
        const PolynomialT<U> *from, const PolynomialT<U> *to,
        PolynomialT<U> *ax, PolynomialT<U> *bx, const Size ax_size = 0,
        const Size bx_size = 0,
        const utils::NTTType ntt_type = utils::NTTType::NEGACYCLIC) const;

    /**
     * @brief Generates an encryption key. The NTT type is derived
     * automatically from the NTT state stored in @p sk.
     * @param sk Secret key to generate public key.
     * @return Newly created encryption key.
     */
    SwitchKeyT<U> genEncKey(const SecretKeyT<U> &sk) const;
    /**
     * @brief Generates an encryption key directly into an existing object.
     * The NTT type is derived automatically from the NTT state stored in @p sk.
     * @param enckey Output storage for encryption key.
     * @param sk Secret key to generate public key.
     */
    void genEncKeyInplace(SwitchKeyT<U> &enckey, const SecretKeyT<U> &sk) const;
    /**
     * @brief Generates a multiplication key used for ciphertext-ciphertext
     * products.
     * @param sk Secret key to generate public key.
     * @return Multiplication key.
     */
    SwitchKeyT<U> genMultKey(const SecretKeyT<U> &sk) const;
    /**
     * @brief Generates a multiplication key directly into an existing object.
     * @param mulkey Output storage for multiplication key.
     * @param sk Secret key to generate public key.
     */
    void genMultKeyInplace(SwitchKeyT<U> &mulkey,
                           const SecretKeyT<U> &sk) const;
    /**
     * @brief Generates a conjugation key for complex conjugate operations.
     * @param sk Secret key to generate public key.
     * @return Conjugation key.
     */
    SwitchKeyT<U> genConjKey(const SecretKeyT<U> &sk) const;
    /**
     * @brief Generates a conjugation key directly into an existing object.
     * @param conjkey Output storage for conjugation key.
     * @param sk Secret key to generate public key.
     */
    void genConjKeyInplace(SwitchKeyT<U> &conjkey,
                           const SecretKeyT<U> &sk) const;
    /**
     * @brief Generates a left rotation key for specific rotate operation.
     * @param rot Rotation index.
     * @param sk Secret key to generate public key.
     * @return Left rotation key of rotation index @p rot.
     */
    SwitchKeyT<U> genLeftRotKey(const Size rot, const SecretKeyT<U> &sk) const;
    /**
     * @brief Generates a left rotation key directly into an existing object.
     * @param rot Rotation index.
     * @param rotkey Output storage for left rotation key.
     * @param sk Secret key to generate public key.
     */
    void genLeftRotKeyInplace(const Size rot, SwitchKeyT<U> &rotkey,
                              const SecretKeyT<U> &sk) const;
    /**
     * @brief Generates a right rotation key for specific rotate operation.
     * @param rot Rotation index.
     * @param sk Secret key to generate public key.
     * @return Right rotation key of rotation index @p rot.
     */
    SwitchKeyT<U> genRightRotKey(const Size rot, const SecretKeyT<U> &sk) const;
    /**
     * @brief Generates a right rotation key directly into an existing object.
     * @param rot Rotation index.
     * @param rotkey Output storage for right rotation key.
     * @param sk Secret key to generate public key.
     */
    void genRightRotKeyInplace(const Size rot, SwitchKeyT<U> &rotkey,
                               const SecretKeyT<U> &sk) const;
    /**
     * @brief Generates an automorphism key identified by the exponent sig.
     * @param sig The power index of the automorphism.
     * @param sk Secret key to generate public key.
     * @return Switching key that realizes the automorphism.
     */
    SwitchKeyT<U> genAutoKey(const Size sig, const SecretKeyT<U> &sk) const;
    /**
     * @brief Generates an automorphism key directly into an existing object.
     * @param sig Automorphism identifier.
     * @param autokey Output storage for automorphism key.
     * @param sk Secret key to generate public key.
     */
    void genAutoKeyInplace(const Size sig, SwitchKeyT<U> &autokey,
                           const SecretKeyT<U> &sk) const;

    /**
     * @brief Generates a composition switch key from an input secret key @p
     * sk_from.
     * @param sk_from Source secret key to be composed into the managed key.
     * @param sk Optional target secret key override.
     * @return Composition key from @p sk_from.
     */
    SwitchKeyT<U> genComposeKey(const SecretKeyT<U> &sk_from,
                                const SecretKeyT<U> &sk) const;
    /**
     * @brief @overload
     * @param coeffs Coefficient vector that describes the source secret key.
     * @param sk Optional target secret key override.
     * @return Composition key from the secret key from @p coeffs.
     */
    SwitchKeyT<U> genComposeKey(const std::vector<i8> coeffs,
                                const SecretKeyT<U> &sk) const;
    /**
     * @brief @overload
     * @param coeffs Pointer to coefficient data.
     * @param size Number of coefficients provided.
     * @param sk Optional target secret key override.
     * @return Composition key from the secret key from @p coeffs.
     */
    SwitchKeyT<U> genComposeKey(const i8 *coeffs, Size size,
                                const SecretKeyT<U> &sk) const;
    /**
     * @brief Generates a composition key directly into an existing object.
     * @param sk_from Source secret key to be composed.
     * @param composekey Output storage for composition key.
     * @param sk Optional target secret key override.
     */
    void genComposeKeyInplace(const SecretKeyT<U> &sk_from,
                              SwitchKeyT<U> &composekey,
                              const SecretKeyT<U> &sk) const;
    /**
     * @brief @overload
     * @param coeffs Coefficient vector describing the source secret key.
     * @param composekey Output storage for composition key.
     * @param sk Optional target secret key override.
     */
    void genComposeKeyInplace(const std::vector<i8> coeffs,
                              SwitchKeyT<U> &composekey,
                              const SecretKeyT<U> &sk) const;
    /**
     * @brief @overload
     * @param coeffs Pointer to coefficient data.
     * @param size Number of coefficients supplied.
     * @param composekey Output storage for composition key.
     * @param sk Optional target secret key override.
     */
    void genComposeKeyInplace(const i8 *coeffs, Size size,
                              SwitchKeyT<U> &composekey,
                              const SecretKeyT<U> &sk) const;

    /**
     * @brief Generates a decomposition key that maps to the provided target
     * secret key @p sk_to.
     * @param sk_to Destination secret key.
     * @param sk Optional source secret key override.
     * @return Decomposition key maps to @p sk_to.
     */
    SwitchKeyT<U> genDecomposeKey(const SecretKeyT<U> &sk_to,
                                  const SecretKeyT<U> &sk) const;
    /**
     * @brief @overload
     * @param coeffs Coefficient vector describing the destination secret key.
     * @param sk Optional source secret key override.
     * @return Decomposition key maps to the secret key from @p coeffs.
     */
    SwitchKeyT<U> genDecomposeKey(const std::vector<i8> coeffs,
                                  const SecretKeyT<U> &sk) const;
    /**
     * @brief @overload
     * @param coeffs Pointer to coefficient data.
     * @param coeffs_size Number of coefficients supplied.
     * @param sk Optional source secret key override.
     * @return Decomposition key maps to the secret key from @p coeffs.
     */
    SwitchKeyT<U> genDecomposeKey(const i8 *coeffs, Size coeffs_size,
                                  const SecretKeyT<U> &sk) const;
    /**
     * @brief Generates a decomposition key directly into an existing object.
     * @param sk_to Destination secret key.
     * @param decompkey Output storage for decomposition key.
     * @param sk Optional source secret key override.
     */
    void genDecomposeKeyInplace(const SecretKeyT<U> &sk_to,
                                SwitchKeyT<U> &decompkey,
                                const SecretKeyT<U> &sk) const;
    /**
     * @brief @overload
     * @param coeffs Destination secret key coefficients.
     * @param decompkey Output storage for decomposition key.
     * @param sk Optional source secret key override.
     */
    void genDecomposeKeyInplace(const std::vector<i8> coeffs,
                                SwitchKeyT<U> &decompkey,
                                const SecretKeyT<U> &sk) const;
    /**
     * @brief @overload
     * @param coeffs Destination secret key coefficients buffer.
     * @param coeffs_size Number of coefficients supplied.
     * @param decompkey Output storage for decomposition key.
     * @param sk Optional source secret key override.
     */
    void genDecomposeKeyInplace(const i8 *coeffs, Size coeffs_size,
                                SwitchKeyT<U> &decompkey,
                                const SecretKeyT<U> &sk) const;

    /**
     * @brief Generates a decomposition key using preset-specific parameters.
     * @param preset_swk Preset that controls switching key layout.
     * @param sk_to Destination secret key.
     * @param sk Optional source secret key override.
     * @return Decomposition key configured for @p preset_swk.
     */
    SwitchKeyT<U> genDecomposeKey(const Preset preset_swk,
                                  const SecretKeyT<U> &sk_to,
                                  const SecretKeyT<U> &sk) const;
    /**
     * @brief @overload
     * @param preset_swk Preset that controls switching key layout.
     * @param coeffs Destination secret key coefficients.
     * @param sk Optional source secret key override.
     * @return Decomposition key configured for @p preset_swk.
     */
    SwitchKeyT<U> genDecomposeKey(const Preset preset_swk,
                                  const std::vector<i8> coeffs,
                                  const SecretKeyT<U> &sk) const;
    /**
     * @brief @overload
     * @param preset_swk Preset that controls switching key layout.
     * @param coeffs Pointer to coefficient data.
     * @param coeffs_size Number of coefficients supplied.
     * @param sk Optional source secret key override.
     * @return Decomposition key configured for @p preset_swk.
     */
    SwitchKeyT<U> genDecomposeKey(const Preset preset_swk, const i8 *coeffs,
                                  Size coeffs_size,
                                  const SecretKeyT<U> &sk) const;
    /**
     * @brief Generate a decomposition key directly into an existing object
     * using preset-specific parameters.
     * @param preset_swk Preset that controls the generated layout.
     * @param sk_to Destination secret key.
     * @param decompkey Output storage for decomposition key.
     * @param sk Optional source secret key override.
     */
    void genDecomposeKeyInplace(const Preset preset_swk,
                                const SecretKeyT<U> &sk_to,
                                SwitchKeyT<U> &decompkey,
                                const SecretKeyT<U> &sk) const;
    /**
     * @brief @overload
     * @param preset_swk Preset that controls the generated layout.
     * @param coeffs Destination secret key coefficients.
     * @param decompkey Output storage for decomposition key.
     * @param sk Optional source secret key override.
     */
    void genDecomposeKeyInplace(const Preset preset_swk,
                                const std::vector<i8> coeffs,
                                SwitchKeyT<U> &decompkey,
                                const SecretKeyT<U> &sk) const;
    /**
     * @brief @overload
     * @param preset_swk Preset that controls the generated layout.
     * @param coeffs Pointer to destination secret key coefficients.
     * @param coeffs_size Number of coefficients supplied.
     * @param decompkey Output storage for decomposition key.
     * @param sk Optional source secret key override.
     */
    void genDecomposeKeyInplace(const Preset preset_swk, const i8 *coeffs,
                                Size coeffs_size, SwitchKeyT<U> &decompkey,
                                const SecretKeyT<U> &sk) const;

    /**
     * @brief Generates a bundle of modulus packing keys between two secret
     * keys.
     * @param sk_from Source secret key.
     * @param sk_to Destination secret key.
     * @return Vector of modpack keys from @p sk_from to @p sk_to.
     */
    std::vector<SwitchKeyT<U>>
    genModPackKeyBundle(const SecretKeyT<U> &sk_from,
                        const SecretKeyT<U> &sk_to) const;
    /**
     * @brief Generate a bundle of modulus packing keys directly into an
     * existing object.
     * @param sk_from Source secret key.
     * @param sk_to Destination secret key.
     * @param key_bundle Output storage for modpack key bundle.
     */
    void
    genModPackKeyBundleInplace(const SecretKeyT<U> &sk_from,
                               const SecretKeyT<U> &sk_to,
                               std::vector<SwitchKeyT<U>> &key_bundle) const;

    // For self modpack
    /**
     * @brief Generates a modulus packing key for self mod-pack operations.
     * @param pad_rank Rank parameter, assumed to be padded power of two.
     * @param sk Secret key to generate public key.
     * @return Modpack keys with @p pad_rank.
     */
    SwitchKeyT<U> genModPackKeyBundle(const Size pad_rank,
                                      const SecretKeyT<U> &sk) const;
    /**
     * @brief Generates a self mod-pack key in-place.
     * @param pad_rank Rank parameter, assumed to be padded power of two.
     * @param modkey Output storage for mod-pack key.
     * @param sk Secret key to generate public key.
     */
    void genModPackKeyBundleInplace(const Size pad_rank, SwitchKeyT<U> &modkey,
                                    const SecretKeyT<U> &sk) const;

private:
    void frobeniusMapInNTT(const PolynomialT<U> &op, const i32 pow,
                           PolynomialT<U> res) const;

    PolynomialT<U> sampleGaussian(const Size num_polyunit) const;

    void sampleUniform(PolynomialT<U> &poly) const;
    void computeConst();

    std::shared_ptr<RandomGenerator> rng_;

    // TODO: move to Context
    std::vector<U> p_mod_;
    std::vector<U> hat_q_i_mod_;
    std::vector<U> hat_q_i_inv_mod_;
    utils::FFT fft_;
};

#ifdef DEB_U64
using KeyGenerator = KeyGeneratorT<>;
#define X(preset) extern template class KeyGeneratorT<PRESET_##preset, u64>;
PRESET_LIST_WITH_EMPTY
#undef X
#endif

// currently, u32 supported runtime preset only
#ifdef DEB_U32
using KeyGenerator32 = KeyGeneratorT<PRESET_EMPTY, u32>;
extern template class KeyGeneratorT<PRESET_EMPTY, u32>;
#endif
} // namespace deb
