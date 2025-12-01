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
#include "utils/Basic.hpp"
#include "utils/FFT.hpp"
#include "utils/ModArith.hpp"

#include "alea/alea.h"

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
    Real scale = 0;            /**< Requested plaintext scale (0 = auto). */
    Size level = DEB_MAX_SIZE; /**< Encryption level override. */
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

// TODO: make template for Encryptor
// to support constexpr functions with various presets
/**
 * @brief Provides CKKS encoding and encryption routines.
 */
class Encryptor {
public:
    /**
     * @brief Constructs an encryptor bound to a preset and optional RNG seed.
     * @param preset Target preset.
     * @param seeds Optional deterministic seed.
     */
    explicit Encryptor(const Preset preset,
                       std::optional<const RNGSeed> seeds = std::nullopt);

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
                      [[maybe_unused]] Ciphertext &ctxt) const {
        throw std::runtime_error(
            "Encryptor::innerEncrypt: Not implemented for this key type");
    }

    template <typename MSG>
    void embeddingToN(const MSG &msg, const Real &delta, Polynomial &ptxt,
                      const Size size) const;

    template <typename MSG>
    void encodeWithoutNTT(const MSG &msg, Polynomial &ptxt, const Size size,
                          const Real scale) const;

    void sampleZO(const Size num_polyunit) const;

    void sampleGaussian(const Size idx, const Size num_polyunit,
                        const bool do_ntt) const;

    Context context_;
    std::shared_ptr<alea_state> as_;
    // compute buffers
    mutable Polynomial ptxt_buffer_;
    mutable Polynomial vx_buffer_;
    mutable std::vector<Polynomial> ex_buffers_;

    // TODO: move to Context
    std::vector<utils::ModArith> modarith_;
    utils::FFTImpl<Real> fft_;
};

// NOLINTBEGIN
#define DECL_ENCRYPT_TEMPLATE_MSG_KEY(msg_t, key_t, prefix)                    \
    prefix template void Encryptor::encrypt<msg_t, key_t>(                     \
        const msg_t &msg, const key_t &key, Ciphertext &ctxt,                  \
        const EncryptOptions &opt) const;                                      \
    prefix template void Encryptor::encrypt<msg_t, key_t>(                     \
        const std::vector<msg_t> &msg, const key_t &key, Ciphertext &ctxt,     \
        const EncryptOptions &opt) const;                                      \
    prefix template void Encryptor::encrypt<msg_t, key_t>(                     \
        const msg_t *msg, const key_t &key, Ciphertext &ctxt,                  \
        const EncryptOptions &opt) const;

#define DECL_ENCRYPT_TEMPLATE_MSG(msg_t, prefix)                               \
    DECL_ENCRYPT_TEMPLATE_MSG_KEY(msg_t, SecretKey, prefix)                    \
    DECL_ENCRYPT_TEMPLATE_MSG_KEY(msg_t, SwitchKey, prefix)                    \
    prefix template void Encryptor::embeddingToN<msg_t>(                       \
        const msg_t &msg, const Real &delta, Polynomial &ptxt,                 \
        const Size size) const;                                                \
    prefix template void Encryptor::encodeWithoutNTT<msg_t>(                   \
        const msg_t &msg, Polynomial &ptxt, const Size size, const Real scale) \
        const;
// NOLINTEND

DECL_ENCRYPT_TEMPLATE_MSG(Message, extern)
DECL_ENCRYPT_TEMPLATE_MSG(CoeffMessage, extern)

} // namespace deb
