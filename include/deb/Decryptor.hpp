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

#include <type_traits>

namespace deb {
// TODO: make template for Decryptor
// to support constexpr functions with various presets
/**
 * @brief Provides CKKS decryption and decoding utilities.
 */
template <Preset P = PRESET_EMPTY> class DecryptorT : public PresetTraits<P> {
#define CV(type, var_name) using PresetTraits<P>::var_name;
    CONST_LIST
#undef CV
    using PresetTraits<P>::modarith;

public:
    /**
     * @brief Creates a decryptor for the given preset.
     * @param preset Target preset that defines polynomial sizes and moduli.
     */
    explicit DecryptorT();
    explicit DecryptorT(const Preset preset);

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
        deb_assert(msg.size() == num_secret,
                   "[Decryptor::decrypt] Message size mismatch");
        decrypt(ctxt, sk, msg.data(), scale);
    }

private:
    Polynomial
    innerDecrypt(const Ciphertext &ctxt, const Polynomial &sx,
                 const std::optional<Polynomial> &ax = std::nullopt) const;
    template <typename CMSG>
    void decodeWithSinglePoly(const Polynomial &ptxt, CMSG &coeff,
                              Real scale) const;
    template <typename CMSG>
    void decodeWithPolyPair(const Polynomial &ptxt, CMSG &coeff,
                            Real scale) const;
    template <typename CMSG>
    void decodeWithoutFFT(const Polynomial &ptxt, CMSG &coeff,
                          Real scale) const;
    template <typename MSG>
    void decode(const Polynomial &ptxt, MSG &msg, Real scale) const;

    utils::FFT fft_;
};

using Decryptor = DecryptorT<>;

#define DECL_DECRYPT_TEMPLATE_MSG(preset, msg_t, prefix)                       \
    prefix template void DecryptorT<preset>::decrypt<msg_t>(                   \
        const Ciphertext &ctxt, const SecretKey &sk, msg_t &msg, Real scale)   \
        const;                                                                 \
    prefix template void DecryptorT<preset>::decrypt<msg_t>(                   \
        const Ciphertext &ctxt, const SecretKey &sk, msg_t *msg, Real scale)   \
        const;                                                                 \
    prefix template void DecryptorT<preset>::decrypt<msg_t>(                   \
        const Ciphertext &ctxt, const SecretKey &sk, std::vector<msg_t> &msg,  \
        Real scale) const;

#define DECL_DECRYPT_TEMPLATE_DECODE(preset, prefix)                           \
    prefix template void                                                       \
    DecryptorT<preset>::decodeWithSinglePoly<CoeffMessage>(                    \
        const Polynomial &ptxt, CoeffMessage &coeff, Real scale) const;        \
    prefix template void                                                       \
    DecryptorT<preset>::decodeWithSinglePoly<FCoeffMessage>(                   \
        const Polynomial &ptxt, FCoeffMessage &coeff, Real scale) const;       \
    prefix template void DecryptorT<preset>::decodeWithPolyPair<CoeffMessage>( \
        const Polynomial &ptxt, CoeffMessage &coeff, Real scale) const;        \
    prefix template void                                                       \
    DecryptorT<preset>::decodeWithPolyPair<FCoeffMessage>(                     \
        const Polynomial &ptxt, FCoeffMessage &coeff, Real scale) const;       \
    prefix template void DecryptorT<preset>::decodeWithoutFFT<CoeffMessage>(   \
        const Polynomial &ptxt, CoeffMessage &coeff, Real scale) const;        \
    prefix template void DecryptorT<preset>::decodeWithoutFFT<FCoeffMessage>(  \
        const Polynomial &ptxt, FCoeffMessage &coeff, Real scale) const;       \
    prefix template void DecryptorT<preset>::decode<Message>(                  \
        const Polynomial &ptxt, Message &msg, Real scale) const;               \
    prefix template void DecryptorT<preset>::decode<FMessage>(                 \
        const Polynomial &ptxt, FMessage &msg, Real scale) const;

#define DECRYPT_TYPE_TEMPLATE(preset, prefix)                                  \
    prefix template class DecryptorT<preset>;                                  \
    DECL_DECRYPT_TEMPLATE_MSG(preset, Message, prefix)                         \
    DECL_DECRYPT_TEMPLATE_MSG(preset, FMessage, prefix)                        \
    DECL_DECRYPT_TEMPLATE_MSG(preset, CoeffMessage, prefix)                    \
    DECL_DECRYPT_TEMPLATE_MSG(preset, FCoeffMessage, prefix)                   \
    DECL_DECRYPT_TEMPLATE_DECODE(preset, prefix)

#define X(preset) DECRYPT_TYPE_TEMPLATE(PRESET_##preset, extern)
PRESET_LIST_WITH_EMPTY
#undef X

} // namespace deb
