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

#include <type_traits>

namespace deb {
// TODO: make template for Decryptor
// to support constexpr functions with various presets
/**
 * @brief Provides CKKS decryption and decoding utilities.
 */
class Decryptor {
public:
    /**
     * @brief Creates a decryptor for the given preset.
     * @param preset Target preset that defines polynomial sizes and moduli.
     */
    explicit Decryptor(const Preset preset);
    // explicit Encryptor(const deb_shared_context_t &context);

    template <typename MSG,
              std::enable_if_t<!std::is_pointer_v<std::decay_t<MSG>>, int> = 0>
    /**
     * @brief Decrypts a ciphertext into a message-like object reference.
     * @tparam MSG Message container or view type.
     * @param ctxt Ciphertext input.
     * @param sk Secret key used for decryption.
     * @param msg Message object that receives decoded values.
     * @param scale Optional scaling override; 0 selects default ciphertext
     * scale.
     */
    void decrypt(const Ciphertext &ctxt, const SecretKey &sk, MSG &msg,
                 Real scale = 0) const;

    template <typename MSG>
    /**
     * @brief Decrypts a ciphertext into a pointer to message storage.
     * @param ctxt Ciphertext input.
     * @param sk Secret key used for decryption.
     * @param msg Pointer to message storage beginning.
     * @param scale Optional scaling override; 0 selects default ciphertext
     * scale.
     */
    void decrypt(const Ciphertext &ctxt, const SecretKey &sk, MSG *msg,
                 Real scale = 0) const;

    template <typename MSG>
    /**
     * @brief Decrypts into a vector-like container, validating secret-unit
     * sizing.
     * @param ctxt Ciphertext input.
     * @param sk Secret key used for decryption.
     * @param msg Vector that receives the decoded data.
     * @param scale Optional scaling override; 0 selects default ciphertext
     * scale.
     */
    void decrypt(const Ciphertext &ctxt, const SecretKey &sk,
                 std::vector<MSG> &msg, Real scale = 0) const {
        deb_assert(msg.size() == context_->get_num_secret(),
                   "[Decryptor::decrypt] Message size mismatch");
        decrypt(ctxt, sk, msg.data(), scale);
    }

private:
    Polynomial
    innerDecrypt(const Ciphertext &ctxt, const SecretKey &sk,
                 const std::optional<Polynomial> &ax = std::nullopt) const;
    void decodeWithSinglePoly(const Polynomial &ptxt, CoeffMessage &coeff,
                              Real scale) const;
    void decodeWithPolyPair(const Polynomial &ptxt, CoeffMessage &coeff,
                            Real scale) const;
    void decodeWithoutFFT(const Polynomial &ptxt, CoeffMessage &coeff,
                          Real scale) const;
    void decode(const Polynomial &ptxt, Message &msg, Real scale) const;

    Context context_;
    // TODO: move to Context
    std::vector<utils::ModArith> modarith_;
    utils::FFTImpl<Real> fft_;
};

#define DECL_DECRYPT_TEMPLATE_MSG(msg_t, prefix)                               \
    prefix template void Decryptor::decrypt<msg_t>(                            \
        const Ciphertext &ctxt, const SecretKey &sk, msg_t &msg, Real scale)   \
        const;                                                                 \
    prefix template void Decryptor::decrypt<msg_t>(                            \
        const Ciphertext &ctxt, const SecretKey &sk, msg_t *msg, Real scale)   \
        const;

#define DECRYPT_TYPE_TEMPLATE(prefix)                                          \
    DECL_DECRYPT_TEMPLATE_MSG(Message, prefix)                                 \
    DECL_DECRYPT_TEMPLATE_MSG(CoeffMessage, prefix)

DECRYPT_TYPE_TEMPLATE(extern)

} // namespace deb
