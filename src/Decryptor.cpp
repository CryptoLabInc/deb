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

#include "Decryptor.hpp"
#include "utils/Basic.hpp"
#include "utils/NTT.hpp"
#include "utils/OmpUtils.hpp"

#include <cstring>
#ifdef DEB_OPENMP
#include <omp.h>
#endif

namespace deb {

constexpr Size MAX_DECRYPT_SIZE = 2;

template <Preset P, typename U> DecryptorT<P, U>::DecryptorT() : DecryptorT(P) {
    if constexpr (P == PRESET_EMPTY) {
        throw std::runtime_error("[Decryptor] Preset template must be "
                                 "specified when preset is not given");
    }
}

template <Preset P, typename U>
DecryptorT<P, U>::DecryptorT(const Preset target_preset)
    : PresetTraits<P, U>(target_preset), fft_(degree << 1) {
    if (target_preset == PRESET_EMPTY) {
        throw std::runtime_error(
            "[Decryptor] Target preset must be "
            "specified when PRESET_EMPTY template is used");
    }
    for (Size i = 0; i < MAX_DECRYPT_SIZE; ++i) {
        modarith.emplace_back(degree, primes[i]);
    }
}

template <Preset P, typename U>
template <typename MSG,
          std::enable_if_t<!std::is_pointer_v<std::decay_t<MSG>>, int>>
void DecryptorT<P, U>::decrypt(const CiphertextT<U> &ctxt,
                               const SecretKeyT<U> &sk, MSG &msg,
                               Real scale) const {
    decrypt(ctxt, sk, &msg, scale);
}

template <Preset P, typename U>
template <typename MSG>
void DecryptorT<P, U>::decrypt(const CiphertextT<U> &ctxt,
                               const SecretKeyT<U> &sk, MSG *msg,
                               Real scale) const {
    if (scale == 0)
        scale = std::pow(2.0, scale_factors[ctxt[0].size() - 1]);
    CiphertextT<U> ctxt_copy =
        ctxt.deepCopy(std::min(ctxt[0].size(), MAX_DECRYPT_SIZE));
    decryptInplace(ctxt_copy, sk, msg, scale);
}
template <Preset P, typename U>
template <typename MSG>
void DecryptorT<P, U>::decryptInplace(CiphertextT<U> &ctxt,
                                      const SecretKeyT<U> &sk, MSG *msg,
                                      Real scale) const {
    deb_assert(ctxt.numPoly() > 0,
               "[Decryptor::decrypt] Ciphertext size is zero");
    deb_assert(sk.numPoly() > 0,
               "[Decryptor::decrypt] Secret key has no embedded polynomials");
    deb_assert(sk[0].size() >= ctxt[0].size(),
               "[Decryptor::decrypt] Level of secret key must be greater than "
               "or equal to ciphertext level");

    if (scale == 0)
        scale = std::pow(2.0, -scale_factors[ctxt[0].size() - 1]);
    else
        scale = 1.0 / scale;

    const int max_num_threads =
        static_cast<int>(ctxt[0].size() * (degree >> 10));
    utils::setOmpThreadLimit(max_num_threads);

    const bool is_real = ctxt.encoding() == REAL;
    const utils::NTTType ntt_type =
        is_real ? utils::NTTType::CYCLIC : utils::NTTType::NEGACYCLIC;
    const Size num_polyunit = std::min(ctxt[0].size(), MAX_DECRYPT_SIZE);
    PolynomialT<U> &ax = ctxt[ctxt.numPoly() - 1];
    ax.setSize(ctxt.preset(), num_polyunit);
    if (!ax[0].isNTT()) {
        forwardNTT(modarith, ax, 0, ntt_type);
    }
    for (Size i = 0; i < num_secret; ++i) {
        CiphertextT<U> ctxt_tmp(ctxt, i);
        ctxt_tmp.setNumPolyunit(num_polyunit);
        for (Size j = 0; j < ctxt_tmp.numPoly(); ++j) {
            if (!ctxt_tmp[j][0].isNTT()) {
                forwardNTT(modarith, ctxt_tmp[j], 0, ntt_type);
            }
        }
        PolynomialT<U> ptxt_tmp = innerDecrypt(ctxt_tmp, sk[i], ax);
        decode(ptxt_tmp, msg[i], scale, is_real);
    }
    utils::unsetOmpThreadLimit();
}

template <Preset P, typename U>
PolynomialT<U>
DecryptorT<P, U>::innerDecrypt(const CiphertextT<U> &ctxt,
                               const PolynomialT<U> &sx,
                               const std::optional<PolynomialT<U>> &ax) const {
    PolynomialT<U> ptxt(preset, std::min(ctxt[0].size(), MAX_DECRYPT_SIZE));
    for (u64 i = 0; i < ptxt.size(); ++i) {
        ptxt[i].setNTT(ctxt[0][i].getNTTType(), ctxt[0][i].getNTTRootType());
    }
    // m = c_0 + (c_1 + ... + (c_{n-1} + c_n * s) * s ... ) * s
    u64 last_idx = ctxt.numPoly() - 1;
    const PolynomialT<U> &tmp =
        (ax.has_value()) ? ax.value() : ctxt[last_idx--];

    PRAGMA_OMP(omp parallel) {
        u64 idx = last_idx;
        mulPolyConst(modarith, tmp, sx, ptxt);
        addPoly(modarith, ptxt, ctxt[idx], ptxt);

        while (idx != 0) {
            mulPolyConst(modarith, ptxt, sx, ptxt);
            addPoly(modarith, ptxt, ctxt[--idx], ptxt);
        }
    }
    return ptxt;
}

template <Preset P, typename U>
template <typename CMSG>
void DecryptorT<P, U>::innerDecode(const PolynomialT<U> &ptxt, CMSG &coeff,
                                   Real scale) const {
    if (ptxt.size() != 1) {
        decodeWithPolyPair(ptxt, coeff, scale);
    } else {
        decodeWithSinglePoly(ptxt, coeff, scale);
    }
}

template <Preset P, typename U>
template <typename MSG>
void DecryptorT<P, U>::decode(const PolynomialT<U> &ptxt, MSG &msg, Real scale,
                              bool is_real) const {

    deb_assert(msg.size() >= num_slots,
               "[Decryptor::decode] Message size is too small");
    if (is_real) {
        deb_assert(
            msg.size() == degree,
            "[Decryptor::decode] For real encoding, message size must be "
            "equal to polynomial degree");
        CoeffMessage coeff(preset);
        innerDecode(ptxt, coeff, scale);
        if constexpr (std::is_same_v<MSG, Message>) {
            msg[0] = {coeff[0], 0};
            for (Size i = 1; i < degree; ++i) {
                msg[i].real(coeff[i]);
                msg[i].imag(-coeff[degree - i]);
            }
            fft_.forwardFFT(msg);
        } else if constexpr (std::is_same_v<MSG, FMessage>) {
            msg[0] = {static_cast<float>(coeff[0]), 0};
            for (Size i = 1; i < degree; ++i) {
                msg[i].real(static_cast<float>(coeff[i]));
                msg[i].imag(static_cast<float>(-coeff[degree - i]));
            }
            fft_.forwardFFT(msg);
        } else if constexpr (std::is_same_v<MSG, CoeffMessage> ||
                             std::is_same_v<MSG, FCoeffMessage>) {
            Message msg_tmp(degree);
            msg_tmp[0] = {coeff[0], 0};
            for (Size i = 1; i < degree; ++i) {
                msg_tmp[i].real(coeff[i]);
                msg_tmp[i].imag(-coeff[degree - i]);
            }
            fft_.forwardFFT(msg_tmp);
            for (Size i = 0; i < msg.size(); ++i) {
                if constexpr (std::is_same_v<MSG, CoeffMessage>) {
                    msg[i] = msg_tmp[i].real();
                } else if constexpr (std::is_same_v<MSG, FCoeffMessage>) {
                    msg[i] = static_cast<float>(msg_tmp[i].real());
                }
            }
        } else {
            throw std::runtime_error(
                "[Decryptor::decode] Unsupported message type");
        }
    } else {
        if constexpr (std::is_same_v<MSG, Message> ||
                      std::is_same_v<MSG, FMessage>) {
            CoeffMessage coeff(preset);
            innerDecode(ptxt, coeff, scale);
            const auto half_degree = num_slots;
            using ScalarT =
                typename std::remove_reference_t<decltype(msg[0])>::value_type;
            for (Size i = 0; i < msg.size(); ++i) {
                msg[i].real(static_cast<ScalarT>(coeff[i]));
                msg[i].imag(static_cast<ScalarT>(coeff[i + half_degree]));
            }
            fft_.forwardFFT(msg);
        } else if constexpr (std::is_same_v<MSG, CoeffMessage> ||
                             std::is_same_v<MSG, FCoeffMessage>) {
            innerDecode(ptxt, msg, scale);
        } else {
            throw std::runtime_error(
                "[Decryptor::decode] Unsupported message type");
        }
    }
}

template <Preset P, typename U>
void DecryptorT<P, U>::changeNTTRootType(utils::NTTRootType root_type) {
    for (Size i = 0; i < num_p; ++i) {
        modarith[i].setNTTRootType(root_type);
    }
}

template <Preset P, typename U>
utils::NTTRootType DecryptorT<P, U>::getNTTRootType() const {
    return modarith[0].getNTTRootType();
}

template <Preset P, typename U>
template <typename CMSG>
void DecryptorT<P, U>::decodeWithSinglePoly(const PolynomialT<U> &ptxt,
                                            CMSG &coeff, Real scale) const {
    const u64 ptxt_degree = ptxt[0].degree();
    const auto full_degree = static_cast<Size>(degree);
    deb_assert(coeff.size() >= ptxt_degree,
               "[Decryptor::decodeWithSinglePoly] Coeff size is too small");

    const u64 prime = primes[0];
    const u64 half_prime = prime >> 1;
    const auto gap = static_cast<Size>(full_degree / ptxt_degree);

    U *interim = ptxt[0].data();

    if (ptxt[0].isNTT()) {
        modarith[0].backwardNTT(interim, ptxt[0].getNTTType());
    }

    Real tmp;

    for (Size i = 0, idx = 0; i < ptxt_degree; i++, idx += gap) {
        if (static_cast<u64>(interim[idx]) > half_prime) {
            tmp = -1.0 *
                  static_cast<Real>(prime - static_cast<u64>(interim[idx]));
        } else {
            tmp = static_cast<Real>(interim[idx]);
        }
        if constexpr (std::is_same_v<CMSG, CoeffMessage>) {
            coeff[i] = tmp * scale;
        } else if constexpr (std::is_same_v<CMSG, FCoeffMessage>) {
            coeff[i] = static_cast<float>(tmp * scale);
        }
    }
}

template <Preset P, typename U>
template <typename CMSG>
void DecryptorT<P, U>::decodeWithPolyPair(const PolynomialT<U> &ptxt,
                                          CMSG &coeff, Real scale) const {
    const auto full_degree = static_cast<Size>(degree);
    const auto ptxt_degree = static_cast<Size>(ptxt[0].degree());
    deb_assert(coeff.size() >= ptxt_degree,
               "[Decryptor::decodeWithPolyPair] Coeff size is too small");

    const U prime0 = static_cast<U>(primes[0]);
    const U prime1 = static_cast<U>(primes[1]);
    const utils::u128 prod_prime = utils::mul64To128(prime0, prime1);
    const utils::u128 half_prod_prime = prod_prime >> 1;
    const U bezout0 = modarith[1].inverse(prime0);
    const U bezout1 = modarith[0].inverse(prime1);

    U *ptxt0 = ptxt[0].data();
    U *ptxt1 = ptxt[1].data();

    if (ptxt[0].isNTT()) {
        modarith[0].backwardNTT(ptxt0, ptxt[0].getNTTType());
        modarith[1].backwardNTT(ptxt1, ptxt[1].getNTTType());
    }
    modarith[0].constMultInPlace(ptxt0, bezout1);
    modarith[1].constMultInPlace(ptxt1, bezout0);

    std::vector<utils::u128> interim(full_degree);

    Real tmp;
    auto gap = static_cast<Size>(full_degree / ptxt_degree);

    PRAGMA_OMP(omp parallel for schedule(static))
    for (Size i = 0; i < full_degree; i++) {
        interim[i] = utils::mul64To128(static_cast<u64>(ptxt0[i]), prime1) +
                     utils::mul64To128(static_cast<u64>(ptxt1[i]), prime0);
        interim[i] =
            (interim[i] >= prod_prime) ? interim[i] - prod_prime : interim[i];
    }

    for (Size i = 0, idx = 0; i < ptxt_degree; i++, idx += gap) {
        if (interim[idx] > half_prod_prime) {
            tmp = -1.0 * static_cast<Real>(prod_prime - interim[idx]);
        } else {
            tmp = static_cast<Real>(interim[idx]);
        }
        if constexpr (std::is_same_v<CMSG, CoeffMessage>) {
            coeff[i] = tmp * scale;
        } else if constexpr (std::is_same_v<CMSG, FCoeffMessage>) {
            coeff[i] = static_cast<float>(tmp * scale);
        } else {
            throw std::runtime_error(
                "[Decryptor::decodeWithPolyPair] Unsupported message type");
        }
    }
}

#ifdef DEB_U64
#define X(preset) DECRYPT_TYPE_TEMPLATE(PRESET_##preset, u64, )
PRESET_LIST_WITH_EMPTY
#undef X
#endif

#ifdef DEB_U32
// currently, u32 supported runtime preset only
DECRYPT_TYPE_TEMPLATE(PRESET_EMPTY, u32, )
#endif

} // namespace deb
