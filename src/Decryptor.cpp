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

#include "Decryptor.hpp"
#include "CKKSTypes.hpp"
#include "utils/Basic.hpp"
#include "utils/NTT.hpp"

#include <cstring>
#ifdef DEB_OPENMP
#include <omp.h>
#endif

namespace deb {

constexpr Size MAX_DECRYPT_SIZE = 2;

Decryptor::Decryptor(const Preset preset)
    : context_(getContext(preset)), fft_(context_->get_degree()) {
    for (Size i = 0; i < MAX_DECRYPT_SIZE; ++i) {
        modarith_.emplace_back(context_->get_degree(),
                               context_->get_primes()[i]);
    }
}

template <typename MSG,
          std::enable_if_t<!std::is_pointer_v<std::decay_t<MSG>>, int>>
void Decryptor::decrypt(const Ciphertext &ctxt, const SecretKey &sk, MSG &msg,
                        Real scale) const {
    decrypt(ctxt, sk, &msg, scale);
}

template <typename MSG>
void Decryptor::decrypt(const Ciphertext &ctxt, const SecretKey &sk, MSG *msg,
                        Real scale) const {
    deb_assert(ctxt.numPoly() > 0,
               "[Decryptor::decrypt] Ciphertext size is zero");
    deb_assert(sk.numPoly() > 0,
               "[Decryptor::decrypt] Secret key has no embedded polynomials");
    deb_assert(sk[0].size() >= ctxt[0].size(),
               "[Decryptor::decrypt] Level of secret key must be greater than "
               "or equal to ciphertext level");
    if (scale == 0)
        scale =
            std::pow(2.0, -context_->get_scale_factors()[ctxt[0].size() - 1]);
    else
        scale = 1.0 / scale;

    const int max_num_threads =
        static_cast<int>(ctxt[0].size() * (context_->get_degree() >> 10));
    setOmpThreadLimit(max_num_threads);

    Ciphertext ctxt_copy =
        ctxt.deepCopy(std::min(ctxt[0].size(), MAX_DECRYPT_SIZE));
    Polynomial &ax = ctxt_copy[ctxt_copy.numPoly() - 1];
    if (!ax[0].isNTT()) {
        forwardNTT(modarith_, ax);
    }
    for (Size i = 0; i < context_->get_num_secret(); ++i) {
        Ciphertext ctxt_tmp(ctxt_copy, i);
        for (Size j = 0; j < ctxt_tmp.numPoly(); ++j) {
            if (!ctxt_tmp[j][0].isNTT()) {
                forwardNTT(modarith_, ctxt_tmp[j]);
            }
        }
        if constexpr (std::is_same_v<MSG, Message>) {
            Polynomial ptxt_tmp = innerDecrypt(ctxt_tmp, sk, ax);
            decode(ptxt_tmp, msg[i], scale);
        } else if constexpr (std::is_same_v<MSG, CoeffMessage>) {
            Polynomial ptxt_tmp = innerDecrypt(ctxt_tmp, sk, ax);
            decodeWithoutFFT(ptxt_tmp, msg[i], scale);
        } else {
            throw std::runtime_error(
                "[Decryptor::decrypt] Unsupported message type");
        }
    }
    unsetOmpThreadLimit();
}

DECRYPT_TYPE_TEMPLATE()

Polynomial Decryptor::innerDecrypt(const Ciphertext &ctxt, const SecretKey &sk,
                                   const std::optional<Polynomial> &ax) const {
    Polynomial ptxt(context_, std::min(ctxt[0].size(), MAX_DECRYPT_SIZE));
    for (u64 i = 0; i < ptxt.size(); ++i) {
        ptxt[i].setNTT(ctxt[0][i].isNTT());
    }
    // m = c_0 + (c_1 + ... + (c_{n-1} + c_n * s) * s ... ) * s
    u64 idx = ctxt.numPoly() - 1;
    const Polynomial &tmp = (ax.has_value()) ? ax.value() : ctxt[idx--];
    PRAGMA_OMP(omp parallel) {
        mulPoly(modarith_, tmp, sk[0], ptxt);
        addPoly(modarith_, ptxt, ctxt[idx], ptxt);

        while (idx != 0) {
            mulPoly(modarith_, ptxt, sk[0], ptxt);
            addPoly(modarith_, ptxt, ctxt[--idx], ptxt);
        }
    }
    return ptxt;
}
void Decryptor::decodeWithSinglePoly(const Polynomial &ptxt,
                                     CoeffMessage &coeff, Real scale) const {
    const u64 ptxt_degree = ptxt[0].degree();
    const auto full_degree = static_cast<Size>(context_->get_degree());
    deb_assert(coeff.size() >= ptxt_degree,
               "[Decryptor::decodeWithSinglePoly] Coeff size is too small");

    const u64 prime = context_->get_primes()[0];
    const u64 half_prime = prime >> 1;
    const auto gap = static_cast<Size>(full_degree / ptxt_degree);

    u64 *interim = ptxt[0].data();

    if (ptxt[0].isNTT()) {
        modarith_[0].backwardNTT(interim);
    }

    Real tmp;

    for (Size i = 0, idx = 0; i < ptxt_degree; i++, idx += gap) {
        if (interim[idx] > half_prime) {
            tmp = -1.0 * static_cast<Real>(prime - interim[idx]);
        } else {
            tmp = static_cast<Real>(interim[idx]);
        }
        coeff[i] = tmp * scale;
    }
}

void Decryptor::decodeWithPolyPair(const Polynomial &ptxt, CoeffMessage &coeff,
                                   Real scale) const {
    // const Real scale_factor = context_->get_scale_factors()[ptxt.size -
    // 1];
    const auto full_degree = static_cast<Size>(context_->get_degree());
    const auto ptxt_degree = static_cast<Size>(ptxt[0].degree());
    deb_assert(coeff.size() >= ptxt_degree,
               "[Decryptor::decodeWithPolyPair] Coeff size is too small");

    const auto prime0 = context_->get_primes()[0];
    const auto prime1 = context_->get_primes()[1];
    const utils::u128 prod_prime = utils::mul64To128(prime0, prime1);
    const utils::u128 half_prod_prime = prod_prime >> 1;
    const u64 bezout0 = modarith_[1].inverse(prime0);
    const u64 bezout1 = modarith_[0].inverse(prime1);

    u64 *ptxt0 = ptxt[0].data();
    u64 *ptxt1 = ptxt[1].data();

    if (ptxt[0].isNTT()) {
        modarith_[0].backwardNTT(ptxt0);
        modarith_[1].backwardNTT(ptxt1);
    }
    modarith_[0].constMultInPlace(ptxt0, bezout1);
    modarith_[1].constMultInPlace(ptxt1, bezout0);

    std::vector<utils::u128> interim(full_degree);
    for (Size i = 0; i < full_degree; i++) {
        interim[i] = utils::mul64To128(ptxt0[i], prime1) +
                     utils::mul64To128(ptxt1[i], prime0);
        interim[i] =
            (interim[i] >= prod_prime) ? interim[i] - prod_prime : interim[i];
    }

    Real tmp;
    auto gap = static_cast<Size>(full_degree / ptxt_degree);

    for (Size i = 0, idx = 0; i < ptxt_degree; i++, idx += gap) {
        if (interim[idx] > half_prod_prime) {
            tmp = -1.0 * static_cast<Real>(prod_prime - interim[idx]);
        } else {
            tmp = static_cast<Real>(interim[idx]);
        }
        coeff[i] = tmp * scale;
    }
}

void Decryptor::decodeWithoutFFT(const Polynomial &ptxt, CoeffMessage &coeff,
                                 Real scale) const {
    if (ptxt.size() != 1) {
        decodeWithPolyPair(ptxt, coeff, scale);
    } else {
        decodeWithSinglePoly(ptxt, coeff, scale);
    }
}

void Decryptor::decode(const Polynomial &ptxt, Message &msg, Real scale) const {

    deb_assert(msg.size() >= context_->get_num_slots(),
               "[Decryptor::decode] Message size is too small");
    CoeffMessage coeff(context_);
    decodeWithoutFFT(ptxt, coeff, scale);

    const auto half_degree = context_->get_num_slots();
    for (Size i = 0; i < msg.size(); ++i) {
        msg[i].real(coeff[i]);
        msg[i].imag(coeff[i + half_degree]);
    }
    fft_.forwardFFT(msg);
}

} // namespace deb
