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
#include "utils/Basic.hpp"
#include "utils/Constant.hpp"
#include "utils/FFT.hpp"
#include "utils/PresetTraits.hpp"
#include "utils/RandomGenerator.hpp"

#include <cstring>
#include <optional>
#include <stdexcept>
#include <type_traits>
#include <vector>

namespace deb {

/**
 * @brief Configures optional behaviors for encryption routines.
 */
struct EncryptOptions {
    Real scale = 0; /**< Requested plaintext scale (0 = auto). */
    Size level = utils::DEB_MAX_SIZE; /**< Encryption level override. */
    bool ntt_out = true; /**< Whether ciphertext output stays in NTT form. */
    bool real_encrypt =
        false; /**< Whether to use the real-encryption method. */
    /**
     * @brief Sets the desired scale value.
     * @param s Requested scale.
     * @return Reference to this for chaining.
     */
    EncryptOptions &Scale(Real s) {
        scale = s;
        return *this;
    }
    /**
     * @brief Sets the desired encryption level.
     * @param l Level index.
     * @return Reference to this for chaining.
     */
    EncryptOptions &Level(Size l) {
        level = l;
        return *this;
    }
    /**
     * @brief Sets whether ciphertext output stays in the NTT domain.
     * @param n NTT flag.
     * @return Reference to this for chaining.
     */
    EncryptOptions &NTTOut(bool n) {
        ntt_out = n;
        return *this;
    }
    /** [deprecated] */
    EncryptOptions &NttOut(bool n) {
        ntt_out = n;
        return *this;
    }
    /**
     * @brief Sets whether to use the real-encryption method.
     * @param r Real-encryption flag.
     * @return Reference to this for chaining.
     */
    EncryptOptions &RealEncrypt(bool r) {
        real_encrypt = r;
        return *this;
    }
};

[[maybe_unused]] static EncryptOptions default_opt;

/**
 * @brief Provides CKKS encoding and encryption routines.
 */
template <Preset P = PRESET_EMPTY, typename U = u64>
class EncryptorT : public PresetTraits<P, U> {
#define CV(type, var_name) using PresetTraits<P, U>::var_name;
    CONST_LIST
#undef CV
    using PresetTraits<P, U>::modarith;

public:
    /**
     * @brief Constructs an encryptor bound to a preset and optional RNG seed.
     * @param target_preset Target preset. Only specified if P is PRESET_EMPTY.
     * @param seeds Optional deterministic seed.
     */
    explicit EncryptorT(std::optional<const RNGSeed> seeds = std::nullopt);
    explicit EncryptorT(Preset target_preset,
                        std::optional<const RNGSeed> seeds = std::nullopt);
    /**
     * @brief Constructs an encryptor with a custom random generator.
     * @param target_preset Target preset.
     * @param rng Custom random generator instance.
     */
    explicit EncryptorT(Preset target_preset,
                        std::shared_ptr<RandomGenerator> rng);

    template <typename MSG, typename KEY,
              std::enable_if_t<!std::is_pointer_v<std::decay_t<MSG>>, int> = 0>
    /**
     * @brief Encrypts a message-like object reference with the provided key.
     * @tparam MSG Message representation type (e.g., Message, FMessage,
     * CoeffMessage, FCoeffMessage).
     * @tparam KEY Secret or switching key type.
     * @param msg Input message object.
     * @param key Secret key or Switching(Encryption) key.
     * @param ctxt Ciphertext that receives the encryption result.
     * @param opt Optional encryption options.
     */
    void encrypt(const MSG &msg, const KEY &key, CiphertextT<U> &ctxt,
                 const EncryptOptions &opt = default_opt) const;

    template <typename MSG, typename KEY>
    /**
     * @brief Encrypts a vector of messages with multi-secret parameters. The
     * message vector size must match num_secret.
     * @param msg Vector with input messages.
     * @param key Secret key or Switching(Encryption) key.
     * @param ctxt Ciphertext result container.
     * @param opt Optional encryption options.
     */
    void encrypt(const std::vector<MSG> &msg, const KEY &key,
                 CiphertextT<U> &ctxt,
                 const EncryptOptions &opt = default_opt) const;

    template <typename MSG, typename KEY>
    /**
     * @brief Encrypts a raw array of messages with multi-secret parameters. The
     * array size must match num_secret.
     * @param msg Pointer to message sequence.
     * @param key Secret key or Switching(Encryption) key.
     * @param ctxt Ciphertext result container.
     * @param opt Optional encryption options.
     */
    void encrypt(const MSG *msg, const KEY &key, CiphertextT<U> &ctxt,
                 const EncryptOptions &opt = default_opt) const;

    template <typename KEY>
    /**
     * @brief Core encryption routine that produces a ciphertext from a
     * plaintext polynomial and key.
     * @tparam KEY Secret or switching key type.
     * @param ptxt Encoded plaintext polynomial.
     * @param key Secret or Switching(Encryption) key.
     * @param num_polyunit Number of PolyUnitT entries to encrypt.
     * @param ctxt Ciphertext result container.
     */
    void innerEncrypt([[maybe_unused]] const PolynomialT<U> &ptxt,
                      [[maybe_unused]] const KEY &key,
                      [[maybe_unused]] Size num_polyunit,
                      [[maybe_unused]] CiphertextT<U> &ctxt) const;

    template <typename MSG>
    /**
     * @brief Core encode routine that embeds a message into a plaintext
     * polynomial.
     * @tparam MSG Message representation type (e.g., Message, FMessage,
     * CoeffMessage, FCoeffMessage).
     * @param msg Input message object.
     * @param delta Scaling factor for embedding.
     * @param ptxt Output plaintext polynomial.
     * @param size Number of PolyUnitT entries to embed.
     */
    void innerEncode(const MSG &msg, const Real &delta, PolynomialT<U> &ptxt,
                     const Size size) const;

    template <typename MSG>
    /**
     * @brief Encodes a message into a plaintext polynomial.
     * @tparam MSG Message representation type (e.g., Message, FMessage,
     * CoeffMessage, FCoeffMessage).
     * @param msg Input message object.
     * @param ptxt Output plaintext polynomial.
     * @param size Number of PolyUnitT entries to encode.
     * @param opt Encryption options (scale and real_encrypt are required).
     */
    void encode(const MSG &msg, PolynomialT<U> &ptxt, const Size size,
                const EncryptOptions &opt) const;

    void changeNTTRootType(const utils::NTTRootType root_type);
    utils::NTTRootType getNTTRootType() const;

private:
    /**
     * @brief Samples a zero-one polynomial.
     * @param num_polyunit Number of PolyUnitT entries to sample.
     * @param ntt_type NTT type to use for the sampled polynomial.
     */
    void sampleZO(const Size num_polyunit, const utils::NTTType ntt_type) const;

    /**
     * @brief Samples a Gaussian polynomial.
     * @param num_polyunit Number of PolyUnitT entries to sample.
     * @param ntt_type NTT type to use for the sampled polynomial.
     */
    void sampleGaussian(const Size num_polyunit,
                        const utils::NTTType ntt_type) const;

    std::shared_ptr<RandomGenerator> rng_;

    // compute buffers
    mutable PolynomialT<U> ptxt_buffer_;
    mutable PolynomialT<U> vx_buffer_;
    mutable PolynomialT<U> ex_buffer_;
    mutable std::vector<U> mask_;
    mutable std::vector<u64> samples_;
    mutable std::vector<i64> i_samples_;

    utils::FFT fft_;
};

// NOLINTBEGIN
#define DECL_ENCRYPT_TEMPLATE_MSG_KEY(preset, u_type, msg_t, key_t, prefix)    \
    prefix template void                                                       \
    EncryptorT<preset, u_type>::encrypt<msg_t, key_t<u_type>>(                 \
        const msg_t &msg, const key_t<u_type> &key, CiphertextT<u_type> &ctxt, \
        const EncryptOptions &opt) const;                                      \
    prefix template void                                                       \
    EncryptorT<preset, u_type>::encrypt<msg_t, key_t<u_type>>(                 \
        const std::vector<msg_t> &msg, const key_t<u_type> &key,               \
        CiphertextT<u_type> &ctxt, const EncryptOptions &opt) const;           \
    prefix template void                                                       \
    EncryptorT<preset, u_type>::encrypt<msg_t, key_t<u_type>>(                 \
        const msg_t *msg, const key_t<u_type> &key, CiphertextT<u_type> &ctxt, \
        const EncryptOptions &opt) const;

#define DECL_ENCRYPT_TEMPLATE_MSG(preset, u_type, msg_t, prefix)               \
    DECL_ENCRYPT_TEMPLATE_MSG_KEY(preset, u_type, msg_t, SecretKeyT, prefix)   \
    DECL_ENCRYPT_TEMPLATE_MSG_KEY(preset, u_type, msg_t, SwitchKeyT, prefix)   \
    prefix template void EncryptorT<preset, u_type>::innerEncode<msg_t>(       \
        const msg_t &msg, const Real &delta, PolynomialT<u_type> &ptxt,        \
        const Size size) const;                                                \
    prefix template void EncryptorT<preset, u_type>::encode<msg_t>(            \
        const msg_t &msg, PolynomialT<u_type> &ptxt, const Size size,          \
        const EncryptOptions &opt) const;

#define DECL_ENCRYPT_TEMPLATE(preset, u_type, prefix)                          \
    prefix template class EncryptorT<preset, u_type>;                          \
    DECL_ENCRYPT_TEMPLATE_MSG(preset, u_type, Message, prefix)                 \
    DECL_ENCRYPT_TEMPLATE_MSG(preset, u_type, FMessage, prefix)                \
    DECL_ENCRYPT_TEMPLATE_MSG(preset, u_type, CoeffMessage, prefix)            \
    DECL_ENCRYPT_TEMPLATE_MSG(preset, u_type, FCoeffMessage, prefix)           \
    prefix template void                                                       \
    EncryptorT<preset, u_type>::innerEncrypt<SecretKeyT<u_type>>(              \
        const PolynomialT<u_type> &ptxt, const SecretKeyT<u_type> &key,        \
        const Size num_polyunit, CiphertextT<u_type> &ctxt) const;             \
    prefix template void                                                       \
    EncryptorT<preset, u_type>::innerEncrypt<SwitchKeyT<u_type>>(              \
        const PolynomialT<u_type> &ptxt, const SwitchKeyT<u_type> &key,        \
        const Size num_polyunit, CiphertextT<u_type> &ctxt) const;
// NOLINTEND

#ifdef DEB_U64
#define X(preset) DECL_ENCRYPT_TEMPLATE(PRESET_##preset, u64, extern)
PRESET_LIST_WITH_EMPTY
#undef X
using Encryptor = EncryptorT<>;
#endif

// currently, u32 supported runtime preset only
#ifdef DEB_U32
DECL_ENCRYPT_TEMPLATE(PRESET_EMPTY, u32, extern)
using Encryptor32 = EncryptorT<PRESET_EMPTY, u32>;
#endif

} // namespace deb
