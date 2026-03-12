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

#include "Encryptor.hpp"
#include "utils/OmpUtils.hpp"

#ifdef DEB_OPENMP
#include <omp.h>
#endif

namespace deb {

template <Preset P>
EncryptorT<P>::EncryptorT(std::optional<const RNGSeed> seeds)
    : PresetTraits<P>(preset), ptxt_buffer_(preset, num_p * num_secret),
      vx_buffer_(preset, true), ex_buffer_(preset, true), samples_(degree),
      mask_(degree), i_samples_(degree), fft_(degree) {
    if constexpr (P == PRESET_EMPTY) {
        throw std::runtime_error(
            "[Encryptor] Preset template must be specified when using this "
            "constructor");
    }

    for (Size i = 0; i < num_p; ++i) {
        modarith.emplace_back(primes[i]);
    }

    if (!seeds) {
        seeds.emplace(SeedGenerator::Gen());
    }
    rng_ = createRandomGenerator(seeds.value());
}

template <Preset P>
EncryptorT<P>::EncryptorT(Preset actual_preset,
                          std::optional<const RNGSeed> seeds)
    : PresetTraits<P>(actual_preset),
      ptxt_buffer_(actual_preset, num_p * num_secret),
      vx_buffer_(actual_preset, true), ex_buffer_(actual_preset, true),
      samples_(degree), mask_(degree), i_samples_(degree), fft_(degree) {

    for (Size i = 0; i < num_p; ++i) {
        modarith.emplace_back(degree, primes[i]);
    }

    if (!seeds) {
        seeds.emplace(SeedGenerator::Gen());
    }
    rng_ = createRandomGenerator(seeds.value());
}

template <Preset P>
EncryptorT<P>::EncryptorT(Preset actual_preset,
                          std::shared_ptr<RandomGenerator> rng)
    : PresetTraits<P>(actual_preset),
      ptxt_buffer_(actual_preset, num_p * num_secret),
      vx_buffer_(actual_preset, true), ex_buffer_(actual_preset, true),
      samples_(degree), mask_(degree), i_samples_(degree), rng_(std::move(rng)),
      fft_(degree) {

    for (Size i = 0; i < num_p; ++i) {
        modarith.emplace_back(degree, primes[i]);
    }
}

template <Preset P>
template <typename MSG, typename KEY,
          std::enable_if_t<!std::is_pointer_v<std::decay_t<MSG>>, int>>
void EncryptorT<P>::encrypt(const MSG &msg, const KEY &key, Ciphertext &ctxt,
                            const EncryptOptions &opt) const {
    deb_assert(num_secret == 1,
               "[Encryptor::encrypt] NumSecret must be 1 for a single message "
               "encryption");
    encrypt(&msg, key, ctxt, opt);
}

template <Preset P>
template <typename MSG, typename KEY>
void EncryptorT<P>::encrypt(const std::vector<MSG> &msg, const KEY &key,
                            Ciphertext &ctxt, const EncryptOptions &opt) const {
    deb_assert(msg.size() == num_secret,
               "[Encryptor::encrypt] Message vector size must match NumSecret");
    encrypt(msg.data(), key, ctxt, opt);
}

template <Preset P>
template <typename MSG, typename KEY>
void EncryptorT<P>::encrypt(const MSG *msg, const KEY &key, Ciphertext &ctxt,
                            const EncryptOptions &opt) const {
    const Size single_num_polyunit = (opt.level == utils::DEB_MAX_SIZE)
                                         ? encryption_level + 1
                                         : opt.level + 1;
    const Size num_polyunit = single_num_polyunit * num_secret;

    deb_assert(single_num_polyunit - 1 <= num_p,
               "[Encryptor::encrypt] Encryption level cannot exceed number of "
               "primes");
    deb_assert((num_secret == 1 || rank == 1),
               "[Encryptor::encrypt] Rank must be 1 when NumSecret > 1"
               " or NumSecret must be 1 when Rank > 1");

    const int max_num_threads =
        static_cast<int>(single_num_polyunit * (degree >> 10));
    utils::setOmpThreadLimit(max_num_threads);

    Polynomial ptxt(ptxt_buffer_, 0, num_polyunit);
    for (Size i = 0; i < num_polyunit; ++i) {
        ptxt[i].setPrime(primes[i % single_num_polyunit]);
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

    if constexpr (std::is_same_v<MSG, Message> ||
                  std::is_same_v<MSG, FMessage>) {
        ctxt.setEncoding(SLOT);
    } else if constexpr (std::is_same_v<MSG, CoeffMessage> ||
                         std::is_same_v<MSG, FCoeffMessage>) {
        ctxt.setEncoding(COEFF);
    } else {
        throw std::runtime_error(
            "[Encryptor::encrypt] Unsupported message type");
    }

    if (!opt.ntt_out) {
        for (u64 i = 0; i < ctxt.numPoly(); ++i) {
            backwardNTT(modarith, ctxt[i]);
        }
    }
    utils::unsetOmpThreadLimit();
}

template <Preset P>
template <typename KEY>
void EncryptorT<P>::innerEncrypt(const Polynomial &ptxt, const KEY &key,
                                 Size num_polyunit, Ciphertext &ctxt) const {
    deb_assert(ptxt.size() >= num_polyunit * num_secret,
               "[Encryptor::innerEncrypt] Level of an input Plaintext "
               "must be greater than or equal to encryption level");
    deb_assert(rank == 1 || num_secret == 1,
               "[Encryptor::innerEncrypt] Rank must be 1 or NumSecret must be "
               "1");
    bool isNTT = ptxt[0].isNTT();
    ctxt.setNumPolyunit(num_polyunit);
    ctxt.setNTT(true);

    if constexpr (std::is_same_v<KEY, SecretKey>) {
        deb_assert(key.numPoly() == num_secret * rank,
                   "[Encryptor::innerEncrypt] Secret key has no embedded "
                   "polynomials.");
        for (u64 i = 0; i < num_polyunit; ++i) {
            rng_->getRandomUint64ArrayInRange(ctxt[num_secret][i].data(),
                                              degree, primes[i]);
        }

        if (rank == 1) {
            std::vector<Polynomial> ptxt_vec;
            for (Size i = 0; i < num_secret; ++i) {
                if (i == 0)
                    ptxt_vec.push_back(ptxt);
                else
                    ptxt_vec.emplace_back(ptxt, i * num_polyunit, num_polyunit);
            }

            PRAGMA_OMP(omp parallel) {
                for (Size i = 0; i < num_secret; ++i) {
                    sampleGaussian(num_polyunit, isNTT);
                    // e = e + m
                    addPoly(modarith, ex_buffer_, ptxt_vec[i], ex_buffer_,
                            num_polyunit);
                    // perform delayed NTT
                    if (!isNTT) {
                        forwardNTT(modarith, ex_buffer_, num_polyunit);
                    }
                    mulPolyConst(modarith, ctxt[num_secret], key[i], ctxt[i]);
                    subPoly(modarith, ex_buffer_, ctxt[i], ctxt[i]);
                }
            }
        } else {
            Polynomial bx(ctxt[0], 0, num_polyunit);
            Polynomial tmp(preset, num_polyunit);

            PRAGMA_OMP(omp parallel) {
                sampleGaussian(num_polyunit, isNTT);

                // e = e + m
                addPoly(modarith, ex_buffer_, ptxt, ex_buffer_, num_polyunit);

                // perform delayed NTT
                if (!isNTT) {
                    forwardNTT(modarith, ex_buffer_, num_polyunit);
                }
                // TODO: not tested yet since no preset of rank > 1
                //  b = - \sigma a_i * s_i + e + m
                for (Size idx = 1; idx < ctxt.numPoly(); ++idx) {
                    mulPolyConst(modarith, ctxt[idx], key[idx - 1], tmp);
                    subPoly(modarith, bx, tmp, bx);
                }
            }
        }
    } else if constexpr (std::is_same_v<KEY, SwitchKey>) {
        if (rank == 1) {
            std::vector<Polynomial> ptxt_vec;
            for (Size i = 0; i < num_secret; ++i) {
                if (i == 0)
                    ptxt_vec.push_back(ptxt);
                else
                    ptxt_vec.emplace_back(ptxt, i * num_polyunit, num_polyunit);
            }

            PRAGMA_OMP(omp parallel) {
                sampleZO(num_polyunit);
                sampleGaussian(num_polyunit, true);
                mulPolyConst(modarith, vx_buffer_, key.ax(0), ctxt[num_secret],
                             num_polyunit);
                addPoly(modarith, ctxt[num_secret], ex_buffer_,
                        ctxt[num_secret]);
                for (Size i = 0; i < num_secret; ++i) {
                    sampleGaussian(num_polyunit, isNTT);
                    mulPoly(modarith, vx_buffer_, key.bx(i), ctxt[i],
                            num_polyunit);
                    addPoly(modarith, ex_buffer_, ptxt_vec[i], ex_buffer_,
                            num_polyunit);

                    if (!isNTT) {
                        forwardNTT(modarith, ex_buffer_, num_polyunit);
                    }

                    addPoly(modarith, ctxt[i], ex_buffer_, ctxt[i]);
                }
            }
        } else {
            // not implemented yet
        }
    } else {
        throw std::runtime_error(
            "[Encryptor::innerEncrypt] Unsupported key type");
    }
}

template <Preset P>
template <typename MSG>
void EncryptorT<P>::embeddingToN(const MSG &msg, const Real &delta,
                                 Polynomial &ptxt, const Size size) const {
    const auto msg_size = msg.size();
    Size gap = degree / msg_size;
    if constexpr (std::is_same_v<MSG, Message>) {
        gap /= 2;
    }
    std::vector<utils::i128> interim(msg_size *
                                     ((std::is_same_v<MSG, Message>) ? 2 : 1));

    for (Size i = 0; i < size; i++) {
        ptxt[i].setNTT(false);
        if (degree > msg_size * ((std::is_same_v<MSG, Message>) ? 2 : 1))
            std::fill_n(ptxt[i].data(), degree, UINT64_C(0));
    }

    PRAGMA_OMP(omp parallel) {
        PRAGMA_OMP(omp for schedule(static))
        for (Size i = 0; i < msg_size; i++) {
            if constexpr (std::is_same_v<MSG, Message> ||
                          std::is_same_v<MSG, FMessage>) {
                interim[i] = static_cast<utils::i128>(
                    utils::addZeroPointFive(msg[i].real() * delta));
                interim[msg_size + i] = static_cast<utils::i128>(
                    utils::addZeroPointFive(msg[i].imag() * delta));
            } else if constexpr (std::is_same_v<MSG, CoeffMessage> ||
                                 std::is_same_v<MSG, FCoeffMessage>) {
                interim[i] = static_cast<utils::i128>(
                    utils::addZeroPointFive(msg[i] * delta));
            }
        }

        PRAGMA_OMP(omp for collapse(2) schedule(static))
        for (Size i = 0; i < size; i++) {
            for (Size j = 0; j < degree / gap; j++) {
                const utils::u128 input = static_cast<utils::u128>(interim[j]);
                utils::u128 sign_mask;
                if constexpr ((utils::i128(-1) >> 1) == utils::i128(-1)) {
                    sign_mask = static_cast<utils::u128>(interim[j] >> 127);
                } else {
                    sign_mask = ~((input >> 127) - static_cast<utils::u128>(1));
                }
                const u64 res =
                    modarith[i].reduceBarrett((input ^ sign_mask) - sign_mask);
                const u64 sign_mask_64 = static_cast<u64>(sign_mask);
                ptxt[i][j * gap] = (res & ~sign_mask_64) |
                                   ((ptxt[i].prime() - res) & sign_mask_64);
            }
        }
    }
}

template <Preset P>
template <typename MSG>
void EncryptorT<P>::encodeWithoutNTT(const MSG &msg, Polynomial &ptxt,
                                     const Size size, const Real scale) const {
    const Real delta{scale == 0 ? std::pow(static_cast<Real>(2),
                                           scale_factors[ptxt.size() - 1])
                                : scale};
    if constexpr (std::is_same_v<MSG, CoeffMessage> ||
                  std::is_same_v<MSG, FCoeffMessage>) {
        embeddingToN(msg, delta, ptxt, size);
    } else if constexpr (std::is_same_v<MSG, Message>) {
        Message tmp(msg.size(), msg.data());
        fft_.backwardFFT(tmp);
        embeddingToN(tmp, delta, ptxt, size);
    } else if constexpr (std::is_same_v<MSG, FMessage>) {
        Message tmp(msg.size());
        for (Size i = 0; i < msg.size(); ++i) {
            tmp[i] = ComplexT<Real>(static_cast<Real>(msg[i].real()),
                                    static_cast<Real>(msg[i].imag()));
        }
        fft_.backwardFFT(tmp);
        embeddingToN(tmp, delta, ptxt, size);
    } else {
        throw std::runtime_error(
            "[Encryptor::encodeWithoutNTT] Unsupported message type");
    }
}

template <Preset P> void EncryptorT<P>::sampleZO(Size num_polyunit) const {

    // const auto pad_degree = std::max(degree, Size(32));
    const auto pad_num = std::max(degree, Size(32)) / 32;
    // std::vector<u64> random_vector(pad_degree);

    PRAGMA_OMP(omp single) {
        vx_buffer_.setNTT(false);
        rng_->getRandomUint64Array(samples_.data() + degree - pad_num, pad_num);
    }

    PRAGMA_OMP(omp for schedule(static))
    for (Size i = 0; i < degree; ++i) {
        u64 &rnd = samples_[i / 32];
        // mask is 0xFFFFFFFF if bit is 1, 0x0 if bit is 0
        mask_[i] = 0UL - ((rnd & 2) >> 1);
        samples_[i] = (rnd & 1);
        rnd >>= 2;
    }

    PRAGMA_OMP(omp for collapse(2) schedule(static))
    for (Size i = 0; i < num_polyunit; ++i) {
        for (Size j = 0; j < degree; ++j) {
            const u64 mask = mask_[j];
            const u64 bit = samples_[j];
            vx_buffer_[i][j] = (bit & mask) | ((primes[i] - bit) & ~mask);
        }
    }

    forwardNTT(modarith, vx_buffer_, num_polyunit);
}

template <Preset P>
void EncryptorT<P>::sampleGaussian(const Size num_polyunit,
                                   const bool do_ntt) const {

    PRAGMA_OMP(omp single) {
        rng_->sampleGaussianInt64Array(i_samples_.data(), degree,
                                       gaussian_error_stdev);
        ex_buffer_.setNTT(false);
    }

    PRAGMA_OMP(omp for collapse(2) schedule(static))
    for (Size i = 0; i < num_polyunit; ++i) {
        for (Size j = 0; j < degree; ++j) {
            const u64 prime = primes[i];
            const u64 sample = static_cast<u64>(i_samples_[j]);

            // sign_mask_rev is -1(0xFFFFFFFF) if i_samples_[j] positive,
            // 0(0x0) if negative
            const u64 sign_mask_rev = (sample >> 63) - 1u;

            ex_buffer_[i][j] =
                (sample & sign_mask_rev) | ((prime + sample) & ~sign_mask_rev);
        }
    }

    if (do_ntt) {
        forwardNTT(modarith, ex_buffer_, num_polyunit);
    }
}

#define X(preset) DECL_ENCRYPT_TEMPLATE(PRESET_##preset, )
PRESET_LIST_WITH_EMPTY
#undef X

} // namespace deb
