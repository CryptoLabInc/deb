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
/**
 * @brief Provides CKKS decryption and decoding utilities.
 */
template <Preset P = PRESET_EMPTY, typename U = u64>
class DecryptorT : public PresetTraits<P, U> {
#define CV(type, var_name) using PresetTraits<P, U>::var_name;
    CONST_LIST
#undef CV
    using PresetTraits<P, U>::modarith;

public:
    /**
     * @brief Creates a decryptor for the given preset.
     * @param target_preset Target preset that defines polynomial sizes and
     * moduli.
     */
    explicit DecryptorT();
    explicit DecryptorT(const Preset target_preset);

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
    void decrypt(const CiphertextT<U> &ctxt, const SecretKeyT<U> &sk, MSG &msg,
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
    void decrypt(const CiphertextT<U> &ctxt, const SecretKeyT<U> &sk, MSG *msg,
                 Real scale = 0) const;

    template <typename MSG>
    void decryptInplace(CiphertextT<U> &ctxt, const SecretKeyT<U> &sk, MSG *msg,
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
    void decrypt(const CiphertextT<U> &ctxt, const SecretKeyT<U> &sk,
                 std::vector<MSG> &msg, Real scale = 0) const {
        deb_assert(msg.size() == num_secret,
                   "[Decryptor::decrypt] Message size mismatch");
        decrypt(ctxt, sk, msg.data(), scale);
    }

    /**
     * @brief Internal decryption function that produces a decrypted polynomial
     * plaintext.
     * @param ctxt Ciphertext input.
     * @param sx Secret key polynomial used for decryption.
     * @param ax Optional auxiliary polynomial for decryption (e.g., from
     * switching key).
     * @return Decrypted polynomial plaintext.
     */
    PolynomialT<U>
    innerDecrypt(const CiphertextT<U> &ctxt, const PolynomialT<U> &sx,
                 const std::optional<PolynomialT<U>> &ax = std::nullopt) const;

    /**
     * @brief Internal decode function that handles both single-poly and
     * poly-pair cases.
     * @tparam CMSG Coefficient message type (e.g., CoeffMessage,
     * FCoeffMessage).
     * @param ptxt Decrypted polynomial plaintext.
     * @param coeff Coefficient message that receives the decoded coefficients.
     * @param scale Scaling factor for decoding.
     */
    template <typename CMSG>
    void innerDecode(const PolynomialT<U> &ptxt, CMSG &coeff, Real scale) const;
    /**
     * @brief Decodes a decrypted polynomial into a message-like object.
     * @tparam MSG Message container or view type.
     * @param ptxt Decrypted polynomial plaintext.
     * @param msg Message object that receives decoded values.
     * @param scale Scaling factor for decoding.
     */
    template <typename MSG>
    void decode(const PolynomialT<U> &ptxt, MSG &msg, Real scale,
                bool is_real) const;

    void changeNTTRootType(const utils::NTTRootType root_type);
    utils::NTTRootType getNTTRootType() const;

private:
    template <typename CMSG>
    void decodeWithSinglePoly(const PolynomialT<U> &ptxt, CMSG &coeff,
                              Real scale) const;
    template <typename CMSG>
    void decodeWithPolyPair(const PolynomialT<U> &ptxt, CMSG &coeff,
                            Real scale) const;

    utils::FFT fft_;
};

#define DECL_DECRYPT_TEMPLATE_MSG(preset, u_type, msg_t, prefix)               \
    prefix template void DecryptorT<preset, u_type>::decrypt<msg_t>(           \
        const CiphertextT<u_type> &ctxt, const SecretKeyT<u_type> &sk,         \
        msg_t &msg, Real scale) const;                                         \
    prefix template void DecryptorT<preset, u_type>::decrypt<msg_t>(           \
        const CiphertextT<u_type> &ctxt, const SecretKeyT<u_type> &sk,         \
        msg_t *msg, Real scale) const;                                         \
    prefix template void DecryptorT<preset, u_type>::decryptInplace<msg_t>(    \
        CiphertextT<u_type> & ctxt, const SecretKeyT<u_type> &sk, msg_t *msg,  \
        Real scale) const;                                                     \
    prefix template void DecryptorT<preset, u_type>::decrypt<msg_t>(           \
        const CiphertextT<u_type> &ctxt, const SecretKeyT<u_type> &sk,         \
        std::vector<msg_t> &msg, Real scale) const;

#define DECL_DECRYPT_TEMPLATE_DECODE(preset, u_type, prefix)                   \
    prefix template void                                                       \
    DecryptorT<preset, u_type>::decodeWithSinglePoly<CoeffMessage>(            \
        const PolynomialT<u_type> &ptxt, CoeffMessage &coeff, Real scale)      \
        const;                                                                 \
    prefix template void                                                       \
    DecryptorT<preset, u_type>::decodeWithSinglePoly<FCoeffMessage>(           \
        const PolynomialT<u_type> &ptxt, FCoeffMessage &coeff, Real scale)     \
        const;                                                                 \
    prefix template void                                                       \
    DecryptorT<preset, u_type>::decodeWithPolyPair<CoeffMessage>(              \
        const PolynomialT<u_type> &ptxt, CoeffMessage &coeff, Real scale)      \
        const;                                                                 \
    prefix template void                                                       \
    DecryptorT<preset, u_type>::decodeWithPolyPair<FCoeffMessage>(             \
        const PolynomialT<u_type> &ptxt, FCoeffMessage &coeff, Real scale)     \
        const;                                                                 \
    prefix template void                                                       \
    DecryptorT<preset, u_type>::innerDecode<CoeffMessage>(                     \
        const PolynomialT<u_type> &ptxt, CoeffMessage &coeff, Real scale)      \
        const;                                                                 \
    prefix template void                                                       \
    DecryptorT<preset, u_type>::innerDecode<FCoeffMessage>(                    \
        const PolynomialT<u_type> &ptxt, FCoeffMessage &coeff, Real scale)     \
        const;                                                                 \
    prefix template void DecryptorT<preset, u_type>::decode<Message>(          \
        const PolynomialT<u_type> &ptxt, Message &msg, Real scale,             \
        bool is_real) const;                                                   \
    prefix template void DecryptorT<preset, u_type>::decode<FMessage>(         \
        const PolynomialT<u_type> &ptxt, FMessage &msg, Real scale,            \
        bool is_real) const;

#define DECRYPT_TYPE_TEMPLATE(preset, u_type, prefix)                          \
    prefix template class DecryptorT<preset, u_type>;                          \
    DECL_DECRYPT_TEMPLATE_MSG(preset, u_type, Message, prefix)                 \
    DECL_DECRYPT_TEMPLATE_MSG(preset, u_type, FMessage, prefix)                \
    DECL_DECRYPT_TEMPLATE_MSG(preset, u_type, CoeffMessage, prefix)            \
    DECL_DECRYPT_TEMPLATE_MSG(preset, u_type, FCoeffMessage, prefix)           \
    DECL_DECRYPT_TEMPLATE_DECODE(preset, u_type, prefix)

#ifdef DEB_U64
using Decryptor = DecryptorT<>;
#define X(preset) DECRYPT_TYPE_TEMPLATE(PRESET_##preset, u64, extern)
PRESET_LIST_WITH_EMPTY
#undef X
#endif

// currently, u32 supported runtime preset only
#ifdef DEB_U32
using Decryptor32 = DecryptorT<PRESET_EMPTY, u32>;
DECRYPT_TYPE_TEMPLATE(PRESET_EMPTY, u32, extern)
#endif

} // namespace deb
