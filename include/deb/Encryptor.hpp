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
    EncryptOptions &NttOut(bool n) {
        ntt_out = n;
        return *this;
    }
};

[[maybe_unused]] static EncryptOptions default_opt;

/**
 * @brief Provides CKKS encoding and encryption routines.
 */
template <Preset P = PRESET_EMPTY> class EncryptorT : public PresetTraits<P> {
#define CV(type, var_name) using PresetTraits<P>::var_name;
    CONST_LIST
#undef CV
    using PresetTraits<P>::modarith;

public:
    /**
     * @brief Constructs an encryptor bound to a preset and optional RNG seed.
     * @param preset Target preset.
     * @param seeds Optional deterministic seed.
     */
    explicit EncryptorT(std::optional<const RNGSeed> seeds = std::nullopt);
    explicit EncryptorT(Preset actual_preset,
                        std::optional<const RNGSeed> seeds = std::nullopt);
    /**
     * @brief Constructs an encryptor with a custom random generator.
     * @param actual_preset Target preset.
     * @param rng Custom random generator instance.
     */
    explicit EncryptorT(Preset actual_preset,
                        std::shared_ptr<RandomGenerator> rng);

    template <typename MSG, typename KEY,
              std::enable_if_t<!std::is_pointer_v<std::decay_t<MSG>>, int> = 0>
    /**
     * @brief Encrypts a message-like object reference with the provided key.
     * @tparam MSG Message representation type.
     * @tparam KEY Secret or switching key type.
     * @param msg Input message object.
     * @param key Encryption key or switch key.
     * @param ctxt Ciphertext that receives the encryption result.
     * @param opt Optional encryption options.
     */
    void encrypt(const MSG &msg, const KEY &key, Ciphertext &ctxt,
                 const EncryptOptions &opt = default_opt) const;

    template <typename MSG, typename KEY>
    /**
     * @brief Encrypts a vector of messages element-wise.
     * @param msg Vector with input messages.
     * @param key Encryption key.
     * @param ctxt Ciphertext result container.
     * @param opt Optional encryption options.
     */
    void encrypt(const std::vector<MSG> &msg, const KEY &key, Ciphertext &ctxt,
                 const EncryptOptions &opt = default_opt) const;

    template <typename MSG, typename KEY>
    /**
     * @brief Encrypts raw message arrays.
     * @param msg Pointer to message sequence.
     * @param key Encryption key.
     * @param ctxt Ciphertext result container.
     * @param opt Optional encryption options.
     */
    void encrypt(const MSG *msg, const KEY &key, Ciphertext &ctxt,
                 const EncryptOptions &opt = default_opt) const;

private:
    template <typename KEY>
    void innerEncrypt([[maybe_unused]] const Polynomial &ptxt,
                      [[maybe_unused]] const KEY &key,
                      [[maybe_unused]] Size num_polyunit,
                      [[maybe_unused]] Ciphertext &ctxt) const;

    template <typename MSG>
    void embeddingToN(const MSG &msg, const Real &delta, Polynomial &ptxt,
                      const Size size) const;

    template <typename MSG>
    void encodeWithoutNTT(const MSG &msg, Polynomial &ptxt, const Size size,
                          const Real scale) const;

    void sampleZO(const Size num_polyunit) const;

    void sampleGaussian(const Size num_polyunit, const bool do_ntt) const;

    std::shared_ptr<RandomGenerator> rng_;
    // compute buffers
    mutable Polynomial ptxt_buffer_;
    mutable Polynomial vx_buffer_;
    mutable Polynomial ex_buffer_;
    mutable std::vector<u64> samples_;
    mutable std::vector<u64> mask_;
    mutable std::vector<i64> i_samples_;

    utils::FFT fft_;
};

using Encryptor = EncryptorT<>;

// NOLINTBEGIN
#define DECL_ENCRYPT_TEMPLATE_MSG_KEY(preset, msg_t, key_t, prefix)            \
    prefix template void EncryptorT<preset>::encrypt<msg_t, key_t>(            \
        const msg_t &msg, const key_t &key, Ciphertext &ctxt,                  \
        const EncryptOptions &opt) const;                                      \
    prefix template void EncryptorT<preset>::encrypt<msg_t, key_t>(            \
        const std::vector<msg_t> &msg, const key_t &key, Ciphertext &ctxt,     \
        const EncryptOptions &opt) const;                                      \
    prefix template void EncryptorT<preset>::encrypt<msg_t, key_t>(            \
        const msg_t *msg, const key_t &key, Ciphertext &ctxt,                  \
        const EncryptOptions &opt) const;

#define DECL_ENCRYPT_TEMPLATE_MSG(preset, msg_t, prefix)                       \
    DECL_ENCRYPT_TEMPLATE_MSG_KEY(preset, msg_t, SecretKey, prefix)            \
    DECL_ENCRYPT_TEMPLATE_MSG_KEY(preset, msg_t, SwitchKey, prefix)            \
    prefix template void EncryptorT<preset>::embeddingToN<msg_t>(              \
        const msg_t &msg, const Real &delta, Polynomial &ptxt,                 \
        const Size size) const;                                                \
    prefix template void EncryptorT<preset>::encodeWithoutNTT<msg_t>(          \
        const msg_t &msg, Polynomial &ptxt, const Size size, const Real scale) \
        const;

#define DECL_ENCRYPT_TEMPLATE(preset, prefix)                                  \
    prefix template class EncryptorT<preset>;                                  \
    DECL_ENCRYPT_TEMPLATE_MSG(preset, Message, prefix)                         \
    DECL_ENCRYPT_TEMPLATE_MSG(preset, FMessage, prefix)                        \
    DECL_ENCRYPT_TEMPLATE_MSG(preset, CoeffMessage, prefix)                    \
    DECL_ENCRYPT_TEMPLATE_MSG(preset, FCoeffMessage, prefix)                   \
    prefix template void EncryptorT<preset>::innerEncrypt<SecretKey>(          \
        const Polynomial &ptxt, const SecretKey &key, const Size num_polyunit, \
        Ciphertext &ctxt) const;                                               \
    prefix template void EncryptorT<preset>::innerEncrypt<SwitchKey>(          \
        const Polynomial &ptxt, const SwitchKey &key, const Size num_polyunit, \
        Ciphertext &ctxt) const;
// NOLINTEND

#define X(preset) DECL_ENCRYPT_TEMPLATE(PRESET_##preset, extern)
PRESET_LIST_WITH_EMPTY
#undef X

} // namespace deb
