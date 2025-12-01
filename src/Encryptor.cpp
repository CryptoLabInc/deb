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

#include "Encryptor.hpp"
#include "CKKSTypes.hpp"
#include "SecretKeyGenerator.hpp"
#include "utils/Basic.hpp"

#include "alea/algorithms.h"

#include <random>

#ifdef DEB_OPENMP
#include <omp.h>
#endif

namespace deb {

Encryptor::Encryptor(const Preset preset, std::optional<const RNGSeed> seeds)
    : context_(getContext(preset)),
      ptxt_buffer_(context_,
                   context_->get_num_p() * context_->get_num_secret()),
      vx_buffer_(context_, true), fft_(context_->get_degree()) {

    for (Size i = 0; i < context_->get_num_p(); ++i) {
        modarith_.emplace_back(context_->get_degree(),
                               context_->get_primes()[i]);
    }
    for (Size i = 0; i < context_->get_num_secret() + 1; ++i) {
        ex_buffers_.emplace_back(context_, true);
    }
    if (!seeds) {
        seeds.emplace(SeedGenerator::Gen());
    }
    as_ = std::shared_ptr<void>(
        alea_init(to_alea_seed(seeds.value()), ALEA_ALGORITHM_SHAKE256),
        [](void *p) { alea_free(static_cast<alea_state *>(p)); });
}

template <typename MSG, typename KEY,
          std::enable_if_t<!std::is_pointer_v<std::decay_t<MSG>>, int>>
void Encryptor::encrypt(const MSG &msg, const KEY &key, Ciphertext &ctxt,
                        const EncryptOptions &opt) const {
    deb_assert(context_->get_num_secret() == 1,
               "[Encryptor::encrypt] NumSecret must be 1 for a single message "
               "encryption");
    encrypt(&msg, key, ctxt, opt);
}

template <typename MSG, typename KEY>
void Encryptor::encrypt(const std::vector<MSG> &msg, const KEY &key,
                        Ciphertext &ctxt, const EncryptOptions &opt) const {
    deb_assert(msg.size() == context_->get_num_secret(),
               "[Encryptor::encrypt] Message vector size must match NumSecret");
    encrypt(msg.data(), key, ctxt, opt);
}

template <typename MSG, typename KEY>
void Encryptor::encrypt(const MSG *msg, const KEY &key, Ciphertext &ctxt,
                        const EncryptOptions &opt) const {
    const Size single_num_polyunit = (opt.level == DEB_MAX_SIZE)
                                         ? context_->get_encryption_level() + 1
                                         : opt.level + 1;
    const Size num_secret = context_->get_num_secret();
    const Size num_polyunit = single_num_polyunit * num_secret;

    deb_assert(
        single_num_polyunit - 1 <= context_->get_num_p(),
        "[Encryptor::encrypt] Encryption level cannot exceed number of primes");
    deb_assert((num_secret == 1 || context_->get_rank() == 1),
               "[Encryptor::encrypt] Rank must be 1 when NumSecret > 1"
               " or NumSecret must be 1 when Rank > 1");

    const int max_num_threads =
        static_cast<int>(single_num_polyunit * (context_->get_degree() >> 10));
    setOmpThreadLimit(max_num_threads);

    Polynomial ptxt(ptxt_buffer_, 0, num_polyunit);
    for (Size i = 0; i < num_polyunit; ++i) {
        ptxt[i].setPrime(context_->get_primes()[i % single_num_polyunit]);
    }

    if (num_secret > 1) {
        for (Size i = 0; i < num_secret; ++i) {
            Polynomial ptxt_tmp(ptxt, single_num_polyunit * i,
                                single_num_polyunit);
            encodeWithoutNTT(msg[i], ptxt_tmp, single_num_polyunit, opt.scale);
        }
    } else {
        encodeWithoutNTT(msg[0], ptxt, single_num_polyunit, opt.scale);
    }
    innerEncrypt(ptxt, key, single_num_polyunit, ctxt);

    if constexpr (std::is_same_v<MSG, Message>) {
        ctxt.setEncoding(SLOT);
    } else if constexpr (std::is_same_v<MSG, CoeffMessage>) {
        ctxt.setEncoding(COEFF);
    } else {
        throw std::runtime_error(
            "[Encryptor::encrypt] Unsupported message type");
    }

    if (!opt.ntt_out) {
        for (u64 i = 0; i < ctxt.numPoly(); ++i) {
            backwardNTT(modarith_, ctxt[i]);
        }
    }
    unsetOmpThreadLimit();
}

template <>
void Encryptor::innerEncrypt<SecretKey>(const Polynomial &ptxt,
                                        const SecretKey &secretkey,
                                        Size num_polyunit,
                                        Ciphertext &ctxt) const {
    const Size rank = context_->get_rank();
    const Size num_secret = context_->get_num_secret();
    deb_assert(ptxt.size() >= num_polyunit * num_secret,
               "[Encryptor::innerEncrypt] Level of an input Plaintext "
               "must be greater than or equal to encryption level");
    deb_assert(
        secretkey.numPoly() == num_secret * rank,
        "[Encryptor::innerEncrypt] Secret key has no embedded polynomials.");
    deb_assert(
        rank == 1 || num_secret == 1,
        "[Encryptor::innerEncrypt] Rank must be 1 or NumSecret must be 1");
    bool isNTT = ptxt[0].isNTT();

    ctxt.setNumPolyunit(num_polyunit);
    ctxt.setNTT(true);

    for (u64 i = 0; i < num_polyunit; ++i) {
        alea_get_random_uint64_array_in_range(
            as_.get(), ctxt[num_secret][i].data(), context_->get_degree(),
            context_->get_primes()[i]);
    }

    if (rank == 1) {
        // std::vector<Polynomial> ex_vec;
        std::vector<Polynomial> ptxt_vec;
        for (Size i = 0; i < num_secret; ++i) {
            sampleGaussian(i, num_polyunit, isNTT);
            if (i == 0)
                ptxt_vec.push_back(ptxt);
            else
                ptxt_vec.emplace_back(ptxt, i * num_polyunit, num_polyunit);
        }

        PRAGMA_OMP(omp parallel) {
            for (Size i = 0; i < num_secret; ++i) {
                // e = e + m
                addPoly(modarith_, ex_buffers_[i], ptxt_vec[i], ex_buffers_[i],
                        num_polyunit);
                // perform delayed NTT
                if (!isNTT) {
                    forwardNTT(modarith_, ex_buffers_[i], num_polyunit);
                }
                mulPoly(modarith_, ctxt[num_secret], secretkey[i], ctxt[i]);
                subPoly(modarith_, ex_buffers_[i], ctxt[i], ctxt[i]);
            }
        }
    } else {
        sampleGaussian(0, num_polyunit, isNTT);

        // e = e + m
        addPoly(modarith_, ex_buffers_[0], ptxt, ex_buffers_[0], num_polyunit);

        // perform delayed NTT
        if (!isNTT) {
            forwardNTT(modarith_, ex_buffers_[0], num_polyunit);
        }
        // TODO: not tested yet since no preset of rank > 1
        //  b = - \sigma a_i * s_i + e + m
        Polynomial bx(ctxt[0], 0, num_polyunit);
        Polynomial tmp(context_, num_polyunit);
        for (Size idx = 1; idx < ctxt.numPoly(); ++idx) {
            mulPoly(modarith_, ctxt[idx], secretkey[idx - 1], tmp);
            subPoly(modarith_, bx, tmp, bx);
        }
    }
}

template <>
void Encryptor::innerEncrypt<SwitchKey>(const Polynomial &ptxt,
                                        const SwitchKey &enckey,
                                        Size num_polyunit,
                                        Ciphertext &ctxt) const {
    const auto rank = context_->get_rank();
    const auto num_secret = context_->get_num_secret();
    deb_assert(ptxt.size() >= num_polyunit * num_secret,
               "[Encryptor::innerEncrypt] Level of an input Plaintext "
               "must be greater than or equal to encryption level");
    deb_assert(
        rank == 1 || num_secret == 1,
        "[Encryptor::innerEncrypt] Rank must be 1 or NumSecret must be 1");

    bool isNTT = ptxt[0].isNTT();
    ctxt.setNumPolyunit(num_polyunit);
    ctxt.setNTT(true);

    sampleZO(num_polyunit);
    sampleGaussian(num_secret, num_polyunit, true);
    if (rank == 1) {
        std::vector<Polynomial> ptxt_vec;
        for (Size i = 0; i < num_secret; ++i) {
            sampleGaussian(i, num_polyunit, isNTT);
            if (i == 0)
                ptxt_vec.push_back(ptxt);
            else
                ptxt_vec.emplace_back(ptxt, i * num_polyunit, num_polyunit);
        }

        PRAGMA_OMP(omp parallel) {
            mulPoly(modarith_, vx_buffer_, enckey.ax(0), ctxt[num_secret],
                    num_polyunit);
            addPoly(modarith_, ctxt[num_secret], ex_buffers_[num_secret],
                    ctxt[num_secret]);
            for (Size i = 0; i < num_secret; ++i) {

                mulPoly(modarith_, vx_buffer_, enckey.bx(i), ctxt[i],
                        num_polyunit);
                addPoly(modarith_, ex_buffers_[i], ptxt_vec[i], ex_buffers_[i],
                        num_polyunit);

                if (!isNTT) {
                    forwardNTT(modarith_, ex_buffers_[i], num_polyunit);
                }

                addPoly(modarith_, ctxt[i], ex_buffers_[i], ctxt[i]);
            }
        }
    } else {
        // not implemented yet
    }
}

template <typename MSG>
void Encryptor::embeddingToN(const MSG &msg, const Real &delta,
                             Polynomial &ptxt, const Size size) const {
    const auto msg_size = msg.size();
    const auto degree = context_->get_degree();
    Size gap = degree / msg_size;
    if constexpr (std::is_same_v<MSG, Message>) {
        gap /= 2;
    }
    std::vector<utils::i128> interim(degree);

    PRAGMA_OMP(omp parallel for schedule(static))
    for (Size i = 0; i < msg_size; i++) {
        if constexpr (std::is_same_v<MSG, Message>) {
            interim[i] = static_cast<utils::i128>(
                utils::addZeroPointFive(msg[i].real() * delta));
            interim[msg_size + i] = static_cast<utils::i128>(
                utils::addZeroPointFive(msg[i].imag() * delta));
        } else if constexpr (std::is_same_v<MSG, CoeffMessage>) {
            interim[i] = static_cast<utils::i128>(
                utils::addZeroPointFive(msg[i] * delta));
        }
    }
    for (Size i = 0; i < size; i++) {
        ptxt[i].setNTT(false);
        if (gap > 1)
            std::fill_n(ptxt[i].data(), degree, UINT64_C(0));
    }

    PRAGMA_OMP(omp parallel for collapse(2) schedule(static))
    for (Size i = 0; i < size; i++) {
        for (Size j = 0; j < degree; j += gap) {
            auto input = interim[j];
            bool is_positive = input >= 0;
            auto abs = is_positive ? input : -input;
            u64 res = modarith_[i].reduceBarrett(static_cast<utils::u128>(abs));
            ptxt[i][j] = is_positive ? res : ptxt[i].prime() - res;
        }
    }
}

template <typename MSG>
void Encryptor::encodeWithoutNTT(const MSG &msg, Polynomial &ptxt,
                                 const Size size, const Real scale) const {
    const Real delta{
        scale == 0 ? std::pow(static_cast<Real>(2),
                              context_->get_scale_factors()[ptxt.size() - 1])
                   : scale};
    if constexpr (std::is_same_v<MSG, CoeffMessage>) {
        embeddingToN(msg, delta, ptxt, size);
    } else if constexpr (std::is_same_v<MSG, Message>) {
        Message tmp(msg.size(), msg.data());
        fft_.backwardFFT(tmp);
        embeddingToN(tmp, delta, ptxt, size);
    } else {
        throw std::runtime_error(
            "[Encryptor::encodeWithoutNTT] Unsupported message type");
    }
}

DECL_ENCRYPT_TEMPLATE_MSG(Message, )
DECL_ENCRYPT_TEMPLATE_MSG(CoeffMessage, )

void Encryptor::sampleZO(Size num_polyunit) const {
    const auto degree = context_->get_degree();

    Polynomial &poly = vx_buffer_;
    poly.setNTT(false);

    const auto pad_degree = (degree + 31) / 32 * 32;
    std::vector<u64> random_vector(pad_degree);

    for (Size i = 0; i < pad_degree; i += 32) {
        u64 rnd = alea_get_random_uint64(as_.get());
        for (Size j = 0; j < 32; j++, rnd >>= 2) {
            // random_vector[i + j] = (rnd & 2) ? (rnd & 1) : -(rnd & 1);
            random_vector[i + j] = ((rnd & 2) - 1) * (rnd & 1);
        }
    }

    const auto *const primes = context_->get_primes();

    PRAGMA_OMP(omp parallel for collapse(2) schedule(static))
    for (Size i = 0; i < num_polyunit; ++i) {
        for (Size j = 0; j < degree; ++j) {
            // poly[i][j] = (random_vector[j] == -1) ? (primes[i] - 1) :
            // random_vector[j];
            poly[i][j] =
                ((1 - random_vector[j]) >> 1) * primes[i] + random_vector[j];
        }
    }
    forwardNTT(modarith_, poly, num_polyunit);
}

void Encryptor::sampleGaussian(const Size idx, const Size num_polyunit,
                               const bool do_ntt) const {
    const auto degree = context_->get_degree();
    const auto *const primes = context_->get_primes();

    std::vector<i64> samples(degree);
    alea_sample_gaussian_int64_array(as_.get(), samples.data(), degree,
                                     context_->get_gaussian_error_stdev());

    Polynomial &poly = ex_buffers_[idx];
    poly.setNTT(false);

    PRAGMA_OMP(omp parallel for schedule(static) collapse(2))
    for (Size i = 0; i < num_polyunit; ++i) {
        for (Size j = 0; j < context_->get_degree(); ++j) {
            // Convert int64_t sample to u64
            poly[i][j] = (samples[j] >= 0)
                             ? static_cast<u64>(samples[j])
                             : primes[i] - static_cast<u64>(-samples[j]);
        }
    }

    if (do_ntt) {
        forwardNTT(modarith_, poly, num_polyunit);
    }
}

} // namespace deb
