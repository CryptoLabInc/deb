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

namespace {
inline uint32_t div_ceil_32(uint32_t degree) { return (degree + 31) / 32; }
inline uint32_t buffer_size(uint32_t degree) {
    return degree + div_ceil_32(degree);
}
} // namespace

namespace deb {

template <Preset P, typename U>
EncryptorT<P, U>::EncryptorT(std::optional<const RNGSeed> seeds)
    : EncryptorT(P, seeds) {
    if constexpr (P == PRESET_EMPTY) {
        throw std::runtime_error(
            "[Encryptor] Preset template must be specified when using this "
            "constructor");
    }
}

template <Preset P, typename U>
EncryptorT<P, U>::EncryptorT(Preset target_preset,
                             std::optional<const RNGSeed> seeds)
    : PresetTraits<P, U>(target_preset),
      rng_(createRandomGenerator(seeds.value_or(SeedGenerator::Gen()))),
      ptxt_buffer_(target_preset, num_p * num_secret),
      vx_buffer_(target_preset, true), ex_buffer_(target_preset, true),
      mask_(degree), samples_(buffer_size(degree)), i_samples_(degree),
      fft_(degree << 1) {
    if (target_preset == PRESET_EMPTY) {
        throw std::runtime_error("[Encryptor] Target preset must be specified "
                                 "when PRESET_EMPTY template is used");
    }
    for (Size i = 0; i < num_p; ++i) {
        modarith.emplace_back(degree, primes[i]);
    }
}

template <Preset P, typename U>
EncryptorT<P, U>::EncryptorT(Preset target_preset,
                             std::shared_ptr<RandomGenerator> rng)
    : PresetTraits<P, U>(target_preset), rng_(std::move(rng)),
      ptxt_buffer_(target_preset, num_p * num_secret),
      vx_buffer_(target_preset, true), ex_buffer_(target_preset, true),
      mask_(degree), samples_(buffer_size(degree)), i_samples_(degree),
      fft_(degree << 1) {

    for (Size i = 0; i < num_p; ++i) {
        modarith.emplace_back(degree, primes[i]);
    }
}

template <Preset P, typename U>
template <typename MSG, typename KEY,
          std::enable_if_t<!std::is_pointer_v<std::decay_t<MSG>>, int>>
void EncryptorT<P, U>::encrypt(const MSG &msg, const KEY &key,
                               CiphertextT<U> &ctxt,
                               const EncryptOptions &opt) const {
    deb_assert(num_secret == 1,
               "[Encryptor::encrypt] NumSecret must be 1 for a single message "
               "encryption");
    encrypt(&msg, key, ctxt, opt);
}

template <Preset P, typename U>
template <typename MSG, typename KEY>
void EncryptorT<P, U>::encrypt(const std::vector<MSG> &msg, const KEY &key,
                               CiphertextT<U> &ctxt,
                               const EncryptOptions &opt) const {
    deb_assert(msg.size() == num_secret,
               "[Encryptor::encrypt] Message vector size must match NumSecret");
    encrypt(msg.data(), key, ctxt, opt);
}

template <Preset P, typename U>
template <typename MSG, typename KEY>
void EncryptorT<P, U>::encrypt(const MSG *msg, const KEY &key,
                               CiphertextT<U> &ctxt,
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

    PolynomialT<U> ptxt(ptxt_buffer_, 0, num_polyunit);
    for (Size i = 0; i < num_polyunit; ++i) {
        ptxt[i].setPrime(primes[i % single_num_polyunit]);
    }

    if (num_secret > 1) {
        for (Size i = 0; i < num_secret; ++i) {
            PolynomialT<U> ptxt_tmp(ptxt, single_num_polyunit * i,
                                    single_num_polyunit);
            encode(msg[i], ptxt_tmp, single_num_polyunit, opt);
        }
    } else {
        encode(msg[0], ptxt, single_num_polyunit, opt);
    }

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
    if (opt.real_encrypt) {
        ctxt.setEncoding(REAL);
    }
    innerEncrypt(ptxt, key, single_num_polyunit, ctxt);

    if (!opt.ntt_out) {
        for (u64 i = 0; i < ctxt.numPoly(); ++i) {
            backwardNTT(modarith, ctxt[i], single_num_polyunit,
                        ctxt[i][0].getNTTType());
        }
    }
    utils::unsetOmpThreadLimit();
}

template <Preset P, typename U>
template <typename KEY>
void EncryptorT<P, U>::innerEncrypt(const PolynomialT<U> &ptxt, const KEY &key,
                                    Size num_polyunit,
                                    CiphertextT<U> &ctxt) const {
    deb_assert(ptxt.size() >= num_polyunit * num_secret,
               "[Encryptor::innerEncrypt] Level of an input Plaintext "
               "must be greater than or equal to encryption level");
    deb_assert(rank == 1 || num_secret == 1,
               "[Encryptor::innerEncrypt] Rank must be 1 or NumSecret must be "
               "1");
    bool isNTT = ptxt[0].isNTT();
    bool cyclicNTT = ctxt.encoding() == REAL;
    utils::NTTType ntt_type =
        cyclicNTT ? utils::NTTType::CYCLIC : utils::NTTType::NEGACYCLIC;
    ctxt.setNumPolyunit(num_polyunit);
    ctxt.setNTT(ntt_type, modarith[0].getNTT(ntt_type)->getRootType());

    if constexpr (std::is_same_v<KEY, SecretKeyT<U>>) {
        deb_assert(key.numPoly() == num_secret * rank,
                   "[Encryptor::innerEncrypt] Secret key has no embedded "
                   "polynomials.");
        for (u64 i = 0; i < num_polyunit; ++i) {
            if constexpr (std::is_same_v<U, u64>) {
                rng_->getRandomUint64ArrayInRange(ctxt[num_secret][i].data(),
                                                  degree, primes[i]);
            } else {
                std::vector<u64> tmp_buf(degree);
                rng_->getRandomUint64ArrayInRange(tmp_buf.data(), degree,
                                                  primes[i]);
                for (Size j = 0; j < degree; ++j)
                    ctxt[num_secret][i][j] = static_cast<U>(tmp_buf[j]);
            }
        }

        if (rank == 1) {
            std::vector<PolynomialT<U>> ptxt_vec;
            for (Size i = 0; i < num_secret; ++i) {
                if (i == 0)
                    ptxt_vec.push_back(ptxt);
                else
                    ptxt_vec.emplace_back(ptxt, i * num_polyunit, num_polyunit);
            }

            PRAGMA_OMP(omp parallel) {
                for (Size i = 0; i < num_secret; ++i) {
                    sampleGaussian(num_polyunit,
                                   isNTT ? ntt_type : utils::NTTType::NONNTT);
                    // e = e + m
                    addPoly(modarith, ex_buffer_, ptxt_vec[i], ex_buffer_,
                            num_polyunit);
                    // perform delayed NTT
                    if (!isNTT) {
                        forwardNTT(modarith, ex_buffer_, num_polyunit,
                                   ntt_type);
                    }
                    mulPolyConst(modarith, ctxt[num_secret], key[i], ctxt[i]);
                    subPoly(modarith, ex_buffer_, ctxt[i], ctxt[i]);
                }
            }
        } else {
            PolynomialT<U> bx(ctxt[0], 0, num_polyunit);
            PolynomialT<U> tmp(preset, num_polyunit);

            PRAGMA_OMP(omp parallel) {
                sampleGaussian(num_polyunit,
                               isNTT ? ntt_type : utils::NTTType::NONNTT);

                // e = e + m
                addPoly(modarith, ex_buffer_, ptxt, ex_buffer_, num_polyunit);

                // perform delayed NTT
                if (!isNTT) {
                    forwardNTT(modarith, ex_buffer_, num_polyunit, ntt_type);
                }
                // TODO: not tested yet since no preset of rank > 1
                //  b = - \sigma a_i * s_i + e + m
                for (Size idx = 1; idx < ctxt.numPoly(); ++idx) {
                    mulPolyConst(modarith, ctxt[idx], key[idx - 1], tmp);
                    subPoly(modarith, bx, tmp, bx);
                }
            }
        }
    } else if constexpr (std::is_same_v<KEY, SwitchKeyT<U>>) {
        if (rank == 1) {
            std::vector<PolynomialT<U>> ptxt_vec;
            for (Size i = 0; i < num_secret; ++i) {
                if (i == 0)
                    ptxt_vec.push_back(ptxt);
                else
                    ptxt_vec.emplace_back(ptxt, i * num_polyunit, num_polyunit);
            }

            PRAGMA_OMP(omp parallel) {
                sampleZO(num_polyunit, ntt_type);
                sampleGaussian(num_polyunit, ntt_type);
                mulPolyConst(modarith, vx_buffer_, key.ax(0), ctxt[num_secret],
                             num_polyunit);
                addPoly(modarith, ctxt[num_secret], ex_buffer_,
                        ctxt[num_secret]);
                for (Size i = 0; i < num_secret; ++i) {
                    sampleGaussian(num_polyunit,
                                   isNTT ? ntt_type : utils::NTTType::NONNTT);
                    mulPoly(modarith, vx_buffer_, key.bx(i), ctxt[i],
                            num_polyunit);
                    addPoly(modarith, ex_buffer_, ptxt_vec[i], ex_buffer_,
                            num_polyunit);

                    if (!isNTT) {
                        forwardNTT(modarith, ex_buffer_, num_polyunit,
                                   ntt_type);
                    }

                    addPoly(modarith, ctxt[i], ex_buffer_, ctxt[i]);
                }
            }
        } else {
            // ctxt[0]       = v * bx(0) + e_0 + m  (b component)
            // ctxt[1..r-1]  = 0                     (unused, zeroed)
            // ctxt[rank]    = v * ax(0) + e_rank    (a component)
            for (Size k = 1; k < rank; ++k) {
                ctxt[k].setNTT(ntt_type,
                               modarith[0].getNTT(ntt_type)->getRootType());
                for (Size i = 0; i < num_polyunit; ++i) {
                    std::fill_n(ctxt[k][i].data(), degree, U(0));
                }
            }

            PRAGMA_OMP(omp parallel) {
                sampleZO(num_polyunit, ntt_type);
                sampleGaussian(num_polyunit, ntt_type);
                mulPolyConst(modarith, vx_buffer_, key.ax(0), ctxt[rank],
                             num_polyunit);
                addPoly(modarith, ctxt[rank], ex_buffer_, ctxt[rank]);

                sampleGaussian(num_polyunit,
                               isNTT ? ntt_type : utils::NTTType::NONNTT);
                mulPoly(modarith, vx_buffer_, key.bx(0), ctxt[0], num_polyunit);
                addPoly(modarith, ex_buffer_, ptxt, ex_buffer_, num_polyunit);
                if (!isNTT) {
                    forwardNTT(modarith, ex_buffer_, num_polyunit, ntt_type);
                }
                addPoly(modarith, ctxt[0], ex_buffer_, ctxt[0]);
            }
        }
    } else {
        throw std::runtime_error(
            "[Encryptor::innerEncrypt] Unsupported key type");
    }
}

template <Preset P, typename U>
template <typename MSG>
void EncryptorT<P, U>::innerEncode(const MSG &msg, const Real &delta,
                                   PolynomialT<U> &ptxt,
                                   const Size size) const {
    const auto msg_size = msg.size();
    Size gap = degree / msg_size;
    if constexpr (std::is_same_v<MSG, Message>) {
        gap /= 2;
    }
    std::vector<utils::i128> interim(msg_size *
                                     ((std::is_same_v<MSG, Message>) ? 2 : 1));

    for (Size i = 0; i < size; i++) {
        ptxt[i].setNTT(utils::NTTType::NONNTT);
        if (degree > msg_size * ((std::is_same_v<MSG, Message>) ? 2 : 1))
            std::fill_n(ptxt[i].data(), degree, U(0));
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
                ptxt[i][j * gap] =
                    static_cast<U>((res & ~sign_mask_64) |
                                   ((ptxt[i].prime() - res) & sign_mask_64));
            }
        }
    }
}

template <Preset P, typename U>
template <typename MSG>
void EncryptorT<P, U>::encode(const MSG &msg, PolynomialT<U> &ptxt,
                              const Size size,
                              const EncryptOptions &opt) const {
    const Real delta{opt.scale == 0 ? std::pow(static_cast<Real>(2),
                                               scale_factors[ptxt.size() - 1])
                                    : opt.scale};

    if (opt.real_encrypt) {
        deb_assert(msg.size() == degree,
                   "[Encryptor::encode] For real encryption, message size must "
                   "match polynomial degree");
        Message tmp(degree);
        if constexpr (std::is_same_v<MSG, CoeffMessage> ||
                      std::is_same_v<MSG, FCoeffMessage>) {
            for (Size i = 0; i < tmp.size(); ++i) {
                tmp[i] = ComplexT<Real>(msg[i], 0);
            }
        } else if constexpr (std::is_same_v<MSG, Message>) {
            std::copy_n(msg.data(), msg.size(), tmp.data());
        } else if constexpr (std::is_same_v<MSG, FMessage>) {
            for (Size i = 0; i < tmp.size(); ++i) {
                tmp[i] = ComplexT<Real>(static_cast<Real>(msg[i].real()), 0);
            }
        } else {
            throw std::runtime_error(
                "[Encryptor::encode] Unsupported message type");
        }
        fft_.backwardFFT(tmp);
        CoeffMessage tmp_coeff(degree);
        for (Size i = 0; i < tmp.size(); ++i) {
            tmp_coeff[i] = static_cast<Real>(tmp[i].real());
        }
        innerEncode(tmp_coeff, delta, ptxt, size);
    } else {
        if constexpr (std::is_same_v<MSG, CoeffMessage> ||
                      std::is_same_v<MSG, FCoeffMessage>) {
            innerEncode(msg, delta, ptxt, size);
        } else if constexpr (std::is_same_v<MSG, Message>) {
            Message tmp(msg.size(), msg.data());
            fft_.backwardFFT(tmp);
            innerEncode(tmp, delta, ptxt, size);
        } else if constexpr (std::is_same_v<MSG, FMessage>) {
            Message tmp(msg.size());
            for (Size i = 0; i < msg.size(); ++i) {
                tmp[i] = ComplexT<Real>(static_cast<Real>(msg[i].real()),
                                        static_cast<Real>(msg[i].imag()));
            }
            fft_.backwardFFT(tmp);
            innerEncode(tmp, delta, ptxt, size);
        } else {
            throw std::runtime_error(
                "[Encryptor::encode] Unsupported message type");
        }
    }
}

template <Preset P, typename U>
void EncryptorT<P, U>::changeNTTRootType(utils::NTTRootType root_type) {
    for (Size i = 0; i < num_p; ++i) {
        modarith[i].setNTTRootType(root_type);
    }
}

template <Preset P, typename U>
utils::NTTRootType EncryptorT<P, U>::getNTTRootType() const {
    return modarith[0].getNTTRootType();
}

template <Preset P, typename U>
void EncryptorT<P, U>::sampleZO(Size num_polyunit,
                                const utils::NTTType ntt_type) const {

    // We sample 64 bits at a time and use 2 bits for each coefficient to sample
    // Assume degree is larger than 32.
    const auto sample_size = div_ceil_32(degree);

    PRAGMA_OMP(omp single) {
        vx_buffer_.setNTT(utils::NTTType::NONNTT);
        // Since this method is in a OMP parallel region, we cannot make local
        // array So sample data into the end of class variable samples_
        rng_->getRandomUint64Array(
            reinterpret_cast<u64 *>(samples_.data() + degree), sample_size);
    }

    PRAGMA_OMP(omp for schedule(static))
    for (Size i = 0; i < degree; ++i) {
        const Size bit_offset = static_cast<Size>((i % 32) * 2);
        const u64 rnd64 =
            reinterpret_cast<const u64 *>(samples_.data() + degree)[i / 32];
        const U rnd = static_cast<U>(rnd64 >> bit_offset);
        // mask is 0xFFFFFFFF if bit is 1, 0x0 if bit is 0
        mask_[i] = U(0) - ((rnd & 2) >> 1);
        samples_[i] = (rnd & 1);
    }

    PRAGMA_OMP(omp for collapse(2) schedule(static))
    for (Size i = 0; i < num_polyunit; ++i) {
        for (Size j = 0; j < degree; ++j) {
            const U mask = mask_[j];
            const U bit = static_cast<U>(samples_[j]);
            vx_buffer_[i][j] =
                (bit & mask) | (static_cast<U>(primes[i] - bit) & ~mask);
        }
    }

    if (ntt_type != utils::NTTType::NONNTT) {
        forwardNTT(modarith, vx_buffer_, num_polyunit, ntt_type);
    }
}

template <Preset P, typename U>
void EncryptorT<P, U>::sampleGaussian(const Size num_polyunit,
                                      const utils::NTTType ntt_type) const {
    // Initialize the buffer with Gaussian samples in standard representation
    PRAGMA_OMP(omp single) {
        rng_->sampleGaussianInt64Array(i_samples_.data(), degree,
                                       gaussian_error_stdev);
        ex_buffer_.setNTT(utils::NTTType::NONNTT);
    }

    PRAGMA_OMP(omp for collapse(2) schedule(static))
    for (Size i = 0; i < num_polyunit; ++i) {
        for (Size j = 0; j < degree; ++j) {
            const u64 prime = primes[i];
            const u64 sample = static_cast<u64>(i_samples_[j]);

            // sign_mask_rev is -1(0xFFFFFFFF) if i_samples_[j] positive,
            // 0(0x0) if negative
            const u64 sign_mask_rev = (sample >> 63) - 1u;

            ex_buffer_[i][j] = static_cast<U>(
                (sample & sign_mask_rev) | ((prime + sample) & ~sign_mask_rev));
        }
    }

    if (ntt_type != utils::NTTType::NONNTT) {
        forwardNTT(modarith, ex_buffer_, num_polyunit, ntt_type);
    }
}

#ifdef DEB_U64
#define X(preset) DECL_ENCRYPT_TEMPLATE(PRESET_##preset, u64, )
PRESET_LIST_WITH_EMPTY
#undef X
#endif

// currently, u32 supported runtime preset only
#ifdef DEB_U32
DECL_ENCRYPT_TEMPLATE(PRESET_EMPTY, u32, )
#endif

} // namespace deb
