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

#include "KeyGenerator.hpp"
#include "SecretKeyGenerator.hpp"
#include "utils/Basic.hpp"

namespace {

inline void checkSecretKey(const deb::Preset preset, const deb::SecretKey &sk) {
    deb_assert(preset == sk.preset(),
               "[KeyGenerator] Preset mismatch between KeyGenerator and "
               "SecretKey.");
    deb_assert(get_rank(preset) * get_num_secret(preset) == sk.numPoly(),
               "[KeyGenerator] Secret key has no embedded polynomials.");
    // Maybe we can remove this check to allow non-NTT secret keys
    deb_assert(sk[0][0].isNTT(),
               "[KeyGenerator] Secret key polynomials are not in NTT domain.");
};

inline void checkSwk(const deb::Preset &preset, const deb::SwitchKey &swk,
                     const deb::SwitchKeyKind expected_type) {
    deb_assert(preset == swk.preset(),
               "[KeyGenerator] Preset mismatch between KeyGenerator and "
               "SwitchingKey.");
    deb_assert(expected_type == swk.type(),
               "[KeyGenerator] The provided switching key has invalid type.");
};

inline void checkModPackKeyBundleCondition(const deb::Preset &preset,
                                           const deb::Preset &preset_from,
                                           const deb::Preset &preset_to) {

    [[maybe_unused]] const deb::Size from_degree = get_degree(preset_from);
    [[maybe_unused]] const deb::Size from_rank = get_rank(preset_from);
    [[maybe_unused]] const deb::Size to_degree = get_degree(preset_to);
    [[maybe_unused]] const deb::Size to_rank = get_rank(preset_to);
    [[maybe_unused]] const deb::Size degree = get_degree(preset);
    // check dimension is compatible
    // check output ctxt dimension could be resulted by a single key switching
    deb_assert(to_degree * to_rank == degree,
               "[genModPackKeyBundle] Total dimension of output secret key is "
               "not "
               "equal to the RLWE encryption dimension");
    // check input ctxt entries can be combined to the output ctxt entries
    deb_assert(to_degree % from_degree == 0,
               "[genModPackKeyBundle] The degree of input secret key does not "
               "divide the degree of output secret key");
    // check the number of combined polys can be packed into to_rank polys
    deb_assert(from_rank % to_rank == 0,
               "[genModPackKeyBundle] The rank of output secret key does not "
               "divide the rank of input secret key");

    // TODO: check prime is compatible
};

inline void automorphism(const deb::i8 *op, deb::i8 *res, const deb::Size sig,
                         const deb::Size degree) {
    // X -> X^{2 * sig + 1}
    deb::Size base = ((sig << 1) ^ 1) & (2 * degree - 1);
    deb::Size idx = 0;
    for (deb::Size i = 0; i < degree; i++) {
        if (idx & degree)
            res[idx & (degree - 1)] = -1 * op[i];
        else
            res[idx] = op[i];
        idx = (idx + base) & (2 * degree - 1);
    }
}
} // anonymous namespace

namespace deb {

template <Preset P>
KeyGeneratorT<P>::KeyGeneratorT(std::optional<const RNGSeed> seeds)
    : KeyGeneratorT(P, std::move(seeds)) {
    if constexpr (P == PRESET_EMPTY) {
        throw std::runtime_error(
            "[KeyGenerator] Preset must be specified for EMPTY preset.");
    }
}

template <Preset P>
KeyGeneratorT<P>::KeyGeneratorT(const Preset preset,
                                std::optional<const RNGSeed> seeds)
    : PresetTraits<P>(preset), fft_(degree) {
    for (u64 i = 0; i < num_p; ++i) {
        modarith.emplace_back(degree, primes[i]);
    }
    if (!seeds) {
        seeds.emplace(SeedGenerator::Gen());
    }
    rng_ = createRandomGenerator(seeds.value());

    computeConst();
}

template <Preset P>
KeyGeneratorT<P>::KeyGeneratorT(const Preset preset,
                                std::shared_ptr<RandomGenerator> rng)
    : PresetTraits<P>(preset), rng_(std::move(rng)), fft_(degree) {
    for (u64 i = 0; i < num_p; ++i) {
        modarith.emplace_back(degree, primes[i]);
    }
    computeConst();
}

template <Preset P>
void KeyGeneratorT<P>::genSwitchingKey(const Polynomial *from,
                                       const Polynomial *to, Polynomial *ax,
                                       Polynomial *bx, const Size ax_size,
                                       const Size bx_size) const {
    const Size length = num_base + num_qp;
    const Size max_length = num_p;
    const Size dnum = gadget_rank;
    const Size alpha = (length + dnum - 1) / dnum;
    Size a_size = ax_size == 0 ? dnum : ax_size;
    Size b_size = bx_size == 0 ? dnum * num_secret : bx_size;

    for (Size i = 0; i < a_size; ++i) {
        sampleUniform(ax[i]);
    }

    Polynomial tmp(preset, max_length);

    const Size s_size = b_size / a_size;
    for (Size idx = 0; idx < a_size; ++idx) {
        const auto &a = ax[idx];
        for (Size sid = 0; sid < s_size; ++sid) {
            auto &b = bx[idx + sid * a_size];
            auto ex = sampleGaussian(max_length, true);

            mulPoly(modarith, a, to[sid], b);
            subPoly(modarith, ex, b, b);

            for (Size tdx = 0; tdx < max_length; ++tdx) {
                if (tdx < idx * alpha ||
                    tdx >= std::min((idx + 1) * alpha, length)) {
                    for (Size i = 0; i < degree; ++i) {
                        tmp[tdx][i] = 0;
                    }
                }
            }
            constMulPoly(modarith, from[sid], p_mod_.data(), tmp, idx * alpha,
                         std::min((idx + 1) * alpha, length));
            constMulPoly(modarith, tmp, hat_q_i_mod_.data(), tmp, idx * alpha,
                         std::min((idx + 1) * alpha, length));
            // TODO: optimize inplace addition
            // addPoly(modarith, b, tmp, b);
            // Polynomial tmp_copy(tmp, idx * alpha,
            //                     std::min(alpha, length - idx * alpha));
            // Polynomial b_copy(b, idx * alpha,
            //                   std::min(alpha, length - idx * alpha));
            // addPoly(modarith, b_copy, tmp_copy, b_copy);
            addPolyConst(modarith, b, tmp, b);
        }
    }
}

template <Preset P>
SwitchKey KeyGeneratorT<P>::genEncKey(const SecretKey &sk) const {
    SwitchKey enckey(preset, SWK_ENC);
    genEncKeyInplace(enckey, sk);
    return enckey;
}

template <Preset P>
void KeyGeneratorT<P>::genEncKeyInplace(SwitchKey &enckey,
                                        const SecretKey &sk) const {
    checkSecretKey(preset, sk);
    checkSwk(preset, enckey, SWK_ENC);
    const bool ntt_state = true; // currently only support ntt state keys
    const Size num_poly = num_p;
    deb_assert(enckey.bxSize() == num_secret && enckey.axSize() == 1,
               "[KeyGenerator::genEncKeyInplace] "
               "The provided switching key has invalid size.");

    sampleUniform(enckey.ax());
    auto ex = sampleGaussian(num_poly, ntt_state);

    for (Size i = 0; i < num_secret; ++i) {
        mulPoly(modarith, enckey.ax(), sk[i], enckey.bx(i));
        subPoly(modarith, ex, enckey.bx(i), enckey.bx(i));
    }
}

template <Preset P>
SwitchKey KeyGeneratorT<P>::genMultKey(const SecretKey &sk) const {
    SwitchKey mulkey(preset, SWK_MULT);
    genMultKeyInplace(mulkey, sk);
    return mulkey;
}

template <Preset P>
void KeyGeneratorT<P>::genMultKeyInplace(SwitchKey &mulkey,
                                         const SecretKey &sk) const {
    checkSecretKey(preset, sk);
    checkSwk(preset, mulkey, SWK_MULT);
    const bool ntt_state = true; // currently only support ntt state keys
    const Size max_length = num_p;
    deb_assert(mulkey.bxSize() == num_secret * mulkey.dnum() &&
                   mulkey.axSize() == mulkey.dnum(),
               "[KeyGenerator::genMultKeyInplace] "
               "The provided switching key has invalid size.");

    std::vector<Polynomial> sx2;
    for (Size i = 0; i < num_secret; ++i) {
        sx2.emplace_back(preset, max_length);
        sx2[i].setNTT(ntt_state);

        mulPoly(modarith, sk[i], sk[i], sx2[i]);
    }
    genSwitchingKey(sx2.data(), sk.data(), mulkey.getAx().data(),
                    mulkey.getBx().data());
    for (Size i = 0; i < sx2.size(); ++i) {
        for (Size j = 0; j < sx2[i].size(); ++j) {
            deb_secure_zero(sx2[i][j].data(), sx2[i][j].degree() * sizeof(u64));
        }
    }
}

template <Preset P>
SwitchKey KeyGeneratorT<P>::genConjKey(const SecretKey &sk) const {
    SwitchKey conjkey(preset, SWK_CONJ);
    genConjKeyInplace(conjkey, sk);
    return conjkey;
}

template <Preset P>
void KeyGeneratorT<P>::genConjKeyInplace(SwitchKey &conjkey,
                                         const SecretKey &sk) const {
    checkSecretKey(preset, sk);
    checkSwk(preset, conjkey, SWK_CONJ);
    const bool ntt_state = sk[0][0].isNTT();

    const Size max_length = num_p;
    deb_assert(conjkey.bxSize() == num_secret * conjkey.dnum() &&
                   conjkey.axSize() == conjkey.dnum(),
               "[KeyGenerator::genConjKeyInplace] "
               "The provided switching key has invalid size.");

    std::vector<Polynomial> sx;
    for (Size i = 0; i < num_secret; ++i) {
        sx.emplace_back(preset, max_length);
        sx[i].setNTT(ntt_state);
        // frobenius map in NTT
        frobeniusMapInNTT(sk[i], -1, sx[i]);
    }

    genSwitchingKey(sx.data(), sk.data(), conjkey.getAx().data(),
                    conjkey.getBx().data());
    for (Size i = 0; i < sx.size(); ++i) {
        for (Size j = 0; j < sx[i].size(); ++j) {
            deb_secure_zero(sx[i][j].data(), sx[i][j].degree() * sizeof(u64));
        }
    }
}

template <Preset P>
SwitchKey KeyGeneratorT<P>::genLeftRotKey(const Size rot,
                                          const SecretKey &sk) const {
    SwitchKey rotkey(preset, SWK_ROT);
    genLeftRotKeyInplace(rot, rotkey, sk);
    return rotkey;
}

template <Preset P>
void KeyGeneratorT<P>::genLeftRotKeyInplace(const Size rot, SwitchKey &rotkey,
                                            const SecretKey &sk) const {
    checkSecretKey(preset, sk);
    checkSwk(preset, rotkey, SWK_ROT);
    deb_assert(rot < num_slots, "[KeyGenerator::genLeftRotKeyInplace] "
                                "Rotation value exceeds number of slots.");
    const auto ntt_state = true; // currently only support ntt state keys

    const Size max_length = num_p;
    deb_assert(rotkey.bxSize() == num_secret * rotkey.dnum() &&
                   rotkey.axSize() == rotkey.dnum(),
               "[KeyGenerator::genLeftRotKeyInplace] "
               "The provided switching key has invalid size.");

    rotkey.setRotIdx(rot);

    std::vector<Polynomial> sx;
    for (Size i = 0; i < num_secret; ++i) {
        sx.emplace_back(preset, max_length);
        sx[i].setNTT(ntt_state);

        frobeniusMapInNTT(sk[i], static_cast<i32>(fft_.getPowerOfFive(rot)),
                          sx[i]);
    }
    genSwitchingKey(sx.data(), sk.data(), rotkey.getAx().data(),
                    rotkey.getBx().data());
    for (Size i = 0; i < sx.size(); ++i) {
        for (Size j = 0; j < sx[i].size(); ++j) {
            deb_secure_zero(sx[i][j].data(), sx[i][j].degree() * sizeof(u64));
        }
    }
}

template <Preset P>
SwitchKey KeyGeneratorT<P>::genRightRotKey(const Size rot,
                                           const SecretKey &sk) const {
    const Size left_rot_id = num_slots - rot;
    SwitchKey rotkey(preset, SWK_ROT);
    genLeftRotKeyInplace(left_rot_id, rotkey, sk);
    return rotkey;
}

template <Preset P>
void KeyGeneratorT<P>::genRightRotKeyInplace(const Size rot, SwitchKey &rotkey,
                                             const SecretKey &sk) const {
    genLeftRotKeyInplace(num_slots - rot, rotkey, sk);
}

template <Preset P>
SwitchKey KeyGeneratorT<P>::genAutoKey(const Size sig,
                                       const SecretKey &sk) const {
    SwitchKey autokey(preset, SWK_AUTO);
    genAutoKeyInplace(sig, autokey, sk);
    return autokey;
}
template <Preset P>
void KeyGeneratorT<P>::genAutoKeyInplace(const Size sig, SwitchKey &autokey,
                                         const SecretKey &sk) const {
    checkSecretKey(preset, sk);
    checkSwk(preset, autokey, SWK_AUTO);
    deb_assert(sig < degree, "[KeyGenerator::genAutoKey] "
                             "Signature value exceeds polynomial degree.");

    deb_assert(autokey.bxSize() == num_secret * autokey.dnum() &&
                   autokey.axSize() == autokey.dnum(),
               "[KeyGenerator::genAutoKey] "
               "The provided switching key has invalid size.");
    autokey.setRotIdx(sig);

    std::vector<i8> coeff_sig(degree * num_secret);

    for (Size i = 0; i < num_secret; ++i) {
        automorphism(sk.coeffs() + i * degree, coeff_sig.data() + i * degree,
                     sig, degree);
    }
    SecretKey sk_sig =
        SecretKeyGenerator::GenSecretKeyFromCoeff(preset, coeff_sig.data());
    genSwitchingKey(sk_sig.data(), sk.data(), autokey.getAx().data(),
                    autokey.getBx().data());
    deb_secure_zero(coeff_sig.data(), coeff_sig.size() * sizeof(i8));
    // sk_sig.zeroize(); // automatically zeroized when going out of scope
}

template <Preset P>
SwitchKey KeyGeneratorT<P>::genComposeKey(const SecretKey &sk_from,
                                          const SecretKey &sk) const {
    // TODO: check prime compatibility
    return genComposeKey(sk_from.coeffs(), sk_from.coeffsSize(), sk);
}
template <Preset P>
SwitchKey KeyGeneratorT<P>::genComposeKey(const std::vector<i8> coeffs,
                                          const SecretKey &sk) const {
    return genComposeKey(coeffs.data(), static_cast<Size>(coeffs.size()), sk);
}
template <Preset P>
SwitchKey KeyGeneratorT<P>::genComposeKey(const i8 *coeffs,
                                          const Size coeffs_size,
                                          const SecretKey &sk) const {
    SwitchKey composekey(preset, SWK_COMPOSE);
    genComposeKeyInplace(coeffs, coeffs_size, composekey, sk);
    return composekey;
}

template <Preset P>
void KeyGeneratorT<P>::genComposeKeyInplace(const SecretKey &sk_from,
                                            SwitchKey &composekey,
                                            const SecretKey &sk) const {
    genComposeKeyInplace(sk_from.coeffs(), sk_from.coeffsSize(), composekey,
                         sk);
}
template <Preset P>
void KeyGeneratorT<P>::genComposeKeyInplace(const std::vector<i8> coeffs,
                                            SwitchKey &composekey,
                                            const SecretKey &sk) const {
    genComposeKeyInplace(coeffs.data(), static_cast<Size>(coeffs.size()),
                         composekey, sk);
}
template <Preset P>
void KeyGeneratorT<P>::genComposeKeyInplace(const i8 *coeffs,
                                            const Size coeffs_size,
                                            SwitchKey &composekey,
                                            const SecretKey &sk) const {
    checkSecretKey(preset, sk);
    checkSwk(preset, composekey, SWK_COMPOSE);

    const Size deg_ratio = degree / coeffs_size;
    deb_assert(coeffs_size * deg_ratio == degree,
               "[KeyGenerator::genComposeKey] "
               "The provided secret key has invalid size.");
    deb_assert(num_secret == 1, "[KeyGenerator::genComposeKey] "
                                "Composition key generation is only supported "
                                "for single-secret presets.");
    deb_assert(composekey.bxSize() == composekey.dnum() &&
                   composekey.axSize() == composekey.dnum(),
               "[KeyGenerator::genComposeKeyInplace] "
               "The provided switching key has invalid size.");

    std::vector<i8> coeffs_embed(degree, 0);
    for (Size i = 0; i < coeffs_size; ++i) {
        coeffs_embed[i * deg_ratio] = coeffs[i];
    }
    SecretKey sk_from =
        SecretKeyGenerator::GenSecretKeyFromCoeff(preset, coeffs_embed.data());

    genSwitchingKey(sk_from.data(), sk.data(), composekey.getAx().data(),
                    composekey.getBx().data());
    // sk_from.zeroize(); // automatically zeroized when going out of scope
}

template <Preset P>
SwitchKey KeyGeneratorT<P>::genDecomposeKey(const SecretKey &sk_to,
                                            const SecretKey &sk) const {
    return genDecomposeKey(sk_to.coeffs(), sk_to.coeffsSize(), sk);
}
template <Preset P>
SwitchKey KeyGeneratorT<P>::genDecomposeKey(const std::vector<i8> coeffs,
                                            const SecretKey &sk) const {
    return genDecomposeKey(coeffs.data(), static_cast<Size>(coeffs.size()), sk);
}
template <Preset P>
SwitchKey KeyGeneratorT<P>::genDecomposeKey(const i8 *coeffs,
                                            const Size coeffs_size,
                                            const SecretKey &sk) const {
    SwitchKey decompkey(preset, SWK_DECOMPOSE);
    genDecomposeKeyInplace(coeffs, coeffs_size, decompkey, sk);

    return decompkey;
}

template <Preset P>
void KeyGeneratorT<P>::genDecomposeKeyInplace(const SecretKey &sk_to,
                                              SwitchKey &decompkey,
                                              const SecretKey &sk) const {
    genDecomposeKeyInplace(sk_to.coeffs(), sk_to.coeffsSize(), decompkey, sk);
}
template <Preset P>
void KeyGeneratorT<P>::genDecomposeKeyInplace(const std::vector<i8> coeffs,
                                              SwitchKey &decompkey,
                                              const SecretKey &sk) const {
    genDecomposeKeyInplace(coeffs.data(), static_cast<Size>(coeffs.size()),
                           decompkey, sk);
}
template <Preset P>
void KeyGeneratorT<P>::genDecomposeKeyInplace(const i8 *coeffs,
                                              const Size coeffs_size,
                                              SwitchKey &decompkey,
                                              const SecretKey &sk) const {
    checkSecretKey(preset, sk);
    checkSwk(preset, decompkey, SWK_DECOMPOSE);
    const Size deg_ratio = degree / coeffs_size;
    deb_assert(coeffs_size * deg_ratio == degree,
               "[KeyGenerator::genDecomposeKey] "
               "The provided secret key has invalid size.");
    deb_assert(num_secret == 1, "[KeyGenerator::genDecomposeKey] "
                                "Decomposition key generation is only "
                                "supported for single-secret presets.");
    deb_assert(decompkey.bxSize() == decompkey.dnum() &&
                   decompkey.axSize() == decompkey.dnum(),
               "[KeyGenerator::genDecomposeKeyInplace] "
               "The provided switching key has invalid size.");

    std::vector<i8> coeffs_embed(degree, 0);
    for (Size i = 0; i < coeffs_size; ++i) {
        coeffs_embed[i * deg_ratio] = coeffs[i];
    }
    SecretKey sk_to =
        SecretKeyGenerator::GenSecretKeyFromCoeff(preset, coeffs_embed.data());
    genSwitchingKey(sk.data(), sk_to.data(), decompkey.getAx().data(),
                    decompkey.getBx().data());
    // sk_to.zeroize(); // automatically zeroized when going out of scope
}

template <Preset P>
SwitchKey KeyGeneratorT<P>::genDecomposeKey(const Preset preset_swk,
                                            const SecretKey &sk_to,
                                            const SecretKey &sk) const {
    return genDecomposeKey(preset_swk, sk_to.coeffs(), sk_to.coeffsSize(), sk);
}
template <Preset P>
SwitchKey KeyGeneratorT<P>::genDecomposeKey(const Preset preset_swk,
                                            const std::vector<i8> coeffs,
                                            const SecretKey &sk) const {
    return genDecomposeKey(preset_swk, coeffs.data(),
                           static_cast<Size>(coeffs.size()), sk);
}
template <Preset P>
SwitchKey KeyGeneratorT<P>::genDecomposeKey(const Preset preset_swk,
                                            const i8 *coeffs, Size coeffs_size,
                                            const SecretKey &sk) const {
    SwitchKey decompkey(preset_swk, SWK_DECOMPOSE);
    genDecomposeKeyInplace(preset_swk, coeffs, coeffs_size, decompkey, sk);
    return decompkey;
}
template <Preset P>
void KeyGeneratorT<P>::genDecomposeKeyInplace(const Preset preset_swk,
                                              const SecretKey &sk_to,
                                              SwitchKey &decompkey,
                                              const SecretKey &sk) const {
    genDecomposeKeyInplace(preset_swk, sk_to.coeffs(), sk_to.coeffsSize(),
                           decompkey, sk);
}
template <Preset P>
void KeyGeneratorT<P>::genDecomposeKeyInplace(const Preset preset_swk,
                                              const std::vector<i8> coeffs,
                                              SwitchKey &decompkey,
                                              const SecretKey &sk) const {
    genDecomposeKeyInplace(preset_swk, coeffs.data(),
                           static_cast<Size>(coeffs.size()), decompkey, sk);
}
template <Preset P>
void KeyGeneratorT<P>::genDecomposeKeyInplace(const Preset preset_swk,
                                              const i8 *coeffs,
                                              Size coeffs_size,
                                              SwitchKey &decompkey,
                                              const SecretKey &sk) const {
    checkSecretKey(preset_swk, sk);
    checkSwk(preset_swk, decompkey, SWK_DECOMPOSE);
    deb_assert(degree == get_degree(preset_swk),
               "[KeyGenerator::genDecomposeKey] "
               "Degree mismatch between KeyGenerator and switching key "
               "preset.");

    const Size num_secret = get_num_secret(preset_swk);
    const Size deg_ratio = get_degree(preset_swk) / coeffs_size;
    deb_assert(coeffs_size * deg_ratio == degree,
               "[KeyGenerator::genDecomposeKey] "
               "The provided secret key has invalid size.");
    deb_assert(num_secret == 1, "[KeyGenerator::genDecomposeKey] "
                                "Decomposition key generation is only "
                                "supported for single-secret presets.");
    deb_assert(decompkey.bxSize() == decompkey.dnum() &&
                   decompkey.axSize() == decompkey.dnum(),
               "[KeyGenerator::genDecomposeKeyInplace] "
               "The provided switching key has invalid size.");

    std::vector<i8> coeffs_embed(degree, 0);
    for (Size i = 0; i < coeffs_size; ++i) {
        coeffs_embed[i * deg_ratio] = coeffs[i];
    }
    SecretKey sk_to = SecretKeyGenerator::GenSecretKeyFromCoeff(
        preset_swk, coeffs_embed.data());
    SecretKey sk_from =
        SecretKeyGenerator::GenSecretKeyFromCoeff(preset_swk, sk.coeffs());
    KeyGenerator keygen_swk(preset_swk);
    keygen_swk.genSwitchingKey(sk_from.data(), sk_to.data(),
                               decompkey.getAx().data(),
                               decompkey.getBx().data());
    // sk_to.zeroize(); // automatically zeroized when going out of scope
    // sk_from.zeroize(); // automatically zeroized when going out of scope
}

template <Preset P>
std::vector<SwitchKey>
KeyGeneratorT<P>::genModPackKeyBundle(const SecretKey &sk_from,
                                      const SecretKey &sk_to) const {
    std::vector<SwitchKey> key_bundle;
    const auto num_key = get_rank(sk_from.preset()) / get_rank(sk_to.preset());
    for (u64 i = 0; i < num_key; ++i) {
        key_bundle.emplace_back(preset, SWK_MODPACK);
    }

    genModPackKeyBundleInplace(sk_from, sk_to, key_bundle);
    return key_bundle;
}

template <Preset P>
void KeyGeneratorT<P>::genModPackKeyBundleInplace(
    const SecretKey &sk_from, const SecretKey &sk_to,
    std::vector<SwitchKey> &key_bundle) const {
    deb_assert(sk_from[0][0].isNTT() == sk_to[0][0].isNTT(),
               "[KeyGenerator::genModPackKeyBundle] "
               "NTT state mismatch between input secret keys.");
    deb_assert(
        get_num_secret(sk_from.preset()) * get_num_secret(sk_to.preset()) == 1,
        "[KeyGenerator::genModPackKeyBundle] "
        "ModPackKeyBundle is only supported for single-secret presets.");

    const auto preset_from = sk_from.preset();
    const auto preset_to = sk_to.preset();
    checkModPackKeyBundleCondition(preset, preset_from, preset_to);

    const u64 from_deg = get_degree(preset_from);
    const u64 from_rank = get_rank(preset_from);
    const u64 to_deg = get_degree(preset_to);
    const u64 to_rank = get_rank(preset_to);
    const u64 rlwe_deg = degree;
    const u64 num_keys = from_rank / to_rank;
    const u64 deg_ratio = rlwe_deg / from_deg;
    deb_assert(key_bundle.size() == num_keys,
               "[KeyGenerator::genModPackKeyBundle] "
               "The provided switching key bundle has invalid size.");

    const i8 *sk_from_coeff = sk_from.coeffs();
    const i8 *sk_to_coeff = sk_to.coeffs();
    auto *rlwe_coeff = new i8[rlwe_deg];

    // to_deg * to_rank -> rlwe_deg ; combine
    for (u64 j = 0; j < to_rank; ++j)
        for (u64 k = 0; k < to_deg; ++k)
            rlwe_coeff[j + to_rank * k] = sk_to_coeff[k + to_deg * j];

    SecretKey sk_to_rlwe =
        SecretKeyGenerator::GenSecretKeyFromCoeff(preset, rlwe_coeff);

    for (u64 i = 0; i < num_keys; ++i) {
        // from_deg * (from_rank / num_keys) -> rlwe_deg ; embed and combine
        // to_rank = from_rank / num_keys
        deb_assert(key_bundle[i].type() == SWK_MODPACK,
                   "[KeyGenerator::genModPackKeyBundle] "
                   "The provided switching key is not a modulus packing key.");
        deb_assert(key_bundle[i].bxSize() ==
                           num_secret * key_bundle[i].dnum() &&
                       key_bundle[i].axSize() == key_bundle[i].dnum(),
                   "[KeyGenerator::genModPackKeyBundle] "
                   "The provided switching key has invalid size.");
        std::fill_n(rlwe_coeff, rlwe_deg, 0);
        for (u64 j = 0; j < to_rank; ++j)
            for (u64 k = 0; k < from_deg; ++k)
                rlwe_coeff[j + deg_ratio * k] =
                    sk_from_coeff[k + from_deg * (j + to_rank * i)];
        SecretKey sk_from_rlwe =
            SecretKeyGenerator::GenSecretKeyFromCoeff(preset, rlwe_coeff);
        genSwitchingKey(sk_from_rlwe.data(), sk_to_rlwe.data(),
                        key_bundle[i].getAx().data(),
                        key_bundle[i].getBx().data());
        // sk_from_rlwe.zeroize(); // automatically zeroized when going out of
        // scope
    }
    deb_secure_zero(rlwe_coeff, rlwe_deg * sizeof(i8));
    delete[] rlwe_coeff;
}

template <Preset P>
SwitchKey KeyGeneratorT<P>::genModPackKeyBundle(const Size pad_rank,
                                                const SecretKey &sk) const {
    SwitchKey modkey(preset, SWK_MODPACK_SELF);
    const auto max_length = num_p;
    modkey.addAx(max_length, pad_rank, true);
    modkey.addBx(max_length, pad_rank * num_secret, true);
    genModPackKeyBundleInplace(pad_rank, modkey, sk);
    return modkey;
}
template <Preset P>
void KeyGeneratorT<P>::genModPackKeyBundleInplace(const Size pad_rank,
                                                  SwitchKey &modkey,
                                                  const SecretKey &sk) const {
    checkSecretKey(preset, sk);
    checkSwk(preset, modkey, SWK_MODPACK_SELF);
    const Size items_per_ctxt = degree / pad_rank;
    deb_assert(utils::isPowerOfTwo(pad_rank),
               "[KeyGenerator::genModPackKeyBundle] pad_rank must be a power "
               "of two.");
    deb_assert(modkey.bxSize() == pad_rank * num_secret &&
                   modkey.axSize() == pad_rank,
               "[KeyGenerator::genModPackKeyBundle] The provided switching key "
               "has invalid size.");

    for (Size i = 0; i < pad_rank; ++i) {
        auto *from_coeff = new i8[degree];
        std::memset(from_coeff, 0, degree);
        for (Size j = 0; j < items_per_ctxt; ++j) {
            from_coeff[pad_rank * j] =
                sk.coeffs()[j * pad_rank + pad_rank - 1 - i];
        }
        SecretKey sk_from =
            SecretKeyGenerator::GenSecretKeyFromCoeff(sk.preset(), from_coeff);
        genSwitchingKey(sk_from.data(), sk.data(), &(modkey.ax(i)),
                        &(modkey.bx(i)), 1, num_secret);
        deb_secure_zero(from_coeff, degree * sizeof(i8));
        delete[] from_coeff;
        // sk_from.zeroize(); // automatically zeroized when going out of scope
    }
}

template <Preset P>
void KeyGeneratorT<P>::frobeniusMapInNTT(const Polynomial &op, const i32 pow,
                                         Polynomial res) const {
    deb_assert(op[0].isNTT(), "[KeyGenerator::frobeniusMapInNTT] "
                              "Input polynomial must be in NTT state.");
    deb_assert(pow % 2 != 0, "[KeyGenerator::frobeniusMapInNTT] "
                             "Frobenius map power must be odd.");

    u64 log_degree = utils::log2floor(static_cast<u64>(degree));

    if (pow == 1) {
        res = op;
    } else if (pow == -1) {
        // PRAGMA_OMP_PARALLEL_FOR
        for (Size i = 0; i < op.size(); ++i) {
            const u64 *ptr_op = op[i].data();
            u64 *ptr_res = res[i].data();

            for (Size j = 0; j < degree; ++j)
                ptr_res[j] = ptr_op[degree - 1 - j];
        }
    } else {
        std::vector<Size> indices(degree);
        for (Size j = 0; j < degree; ++j) {
            Size reversed = utils::bitReverse(j, log_degree);
            Size index_raw = static_cast<Size>(pow) * (2 * reversed + 1);
            index_raw %= (degree * 2);
            Size index = (index_raw - 1) >> 1;
            indices[j] = utils::bitReverse(index, log_degree);
        }

        // PRAGMA_OMP_PARALLEL_FOR
        for (Size i = 0; i < op.size(); ++i) {
            const u64 *ptr_op = op[i].data();
            u64 *ptr_res = res[i].data();

            for (Size j = 0; j < degree; ++j)
                ptr_res[j] = ptr_op[indices[j]];
        }
    }
}

template <Preset P>
Polynomial KeyGeneratorT<P>::sampleGaussian(const Size num_polyunit,
                                            bool do_ntt) const {
    std::vector<i64> samples(degree);
    rng_->sampleGaussianInt64Array(samples.data(), degree,
                                   gaussian_error_stdev);
    Polynomial poly(preset, num_polyunit);
    for (Size i = 0; i < poly.size(); ++i) {
        poly[i].setPrime(primes[i]);
        for (Size j = 0; j < degree; ++j) {
            // Convert int64_t sample to u64
            poly[i][j] = (samples[j] >= 0)
                             ? static_cast<u64>(samples[j])
                             : primes[i] - static_cast<u64>(-samples[j]);
        }
    }

    if (do_ntt) {
        forwardNTT(modarith, poly);
    }
    return poly;
}

template <Preset P>
void KeyGeneratorT<P>::sampleUniform(Polynomial &poly) const {
    // TODO: add reseed controller
    for (u64 i = 0; i < poly.size(); ++i) {
        rng_->getRandomUint64ArrayInRange(poly[i].data(), degree,
                                          poly[i].prime());
    }
}

template <Preset P> void KeyGeneratorT<P>::computeConst() {
    const Size length = num_base + num_qp;
    const Size dnum = gadget_rank;
    const Size alpha = (length + dnum - 1) / dnum;

    p_mod_.resize(length);
    for (Size i = 0; i < length; ++i) {
        const u64 prime = primes[i];
        const u64 two_prime = prime << 1;
        u64 p = UINT64_C(1);

        for (Size j = 0; j < num_tp; ++j) {
            const u64 pp =
                modarith[i].template reduceBarrett<2>(primes[j + length]);
            p = modarith[i].mul(p, pp);
        }
        p = utils::subIfGE(p, two_prime);
        p_mod_[i] = utils::subIfGE(p, prime);
    }

    hat_q_i_mod_.resize(length);
    hat_q_i_inv_mod_.resize(length);

    for (Size i = 0; i < length; ++i) {
        const u64 beta = i / alpha;
        const u64 prime = primes[i];
        const u64 two_prime = prime << 1;
        u64 hat_q = UINT64_C(1);

        for (Size j = 0; j < length; ++j) {
            if (j < beta * alpha || j >= (beta + 1) * alpha) {
                u64 pp = modarith[i].template reduceBarrett<2>(primes[j]);
                hat_q = modarith[i].mul(hat_q, pp);
            }
        }

        hat_q = utils::subIfGE(hat_q, two_prime);
        hat_q = utils::subIfGE(hat_q, prime);

        hat_q_i_mod_[i] = hat_q;
        hat_q_i_inv_mod_[i] = modarith[i].inverse(hat_q);
    }
}

#define X(preset) template class KeyGeneratorT<PRESET_##preset>;
PRESET_LIST_WITH_EMPTY
#undef X
} // namespace deb
