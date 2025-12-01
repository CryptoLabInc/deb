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

#include "KeyGenerator.hpp"
#include "SecretKeyGenerator.hpp"

#include "utils/Basic.hpp"

#include <random>

#include <iostream>

namespace {

inline void checkSecretKey(const deb::Context &context,
                           const std::optional<deb::SecretKey> &sk) {
    deb_assert(sk.has_value(), "[KeyGenerator] Secret key is not set.");
    deb_assert(context->get_preset() == sk->preset(),
               "[KeyGenerator] Preset mismatch between KeyGenerator and "
               "SecretKey.");
    deb_assert(sk->numPoly() == context->get_rank() * context->get_num_secret(),
               "[KeyGenerator] Secret key has no embedded polynomials.");
    // Maybe we can remove this check to allow non-NTT secret keys
    deb_assert((*sk)[0][0].isNTT(),
               "[KeyGenerator] Secret key polynomials are not in NTT domain.");
};

inline void checkSwk(const deb::Context &context, const deb::SwitchKey &swk,
                     const deb::SwitchKeyKind expected_type) {
    deb_assert(context->get_preset() == swk.preset(),
               "[KeyGenerator] Preset mismatch between KeyGenerator and "
               "SwitchingKey.");
    deb_assert(swk.type() == expected_type,
               "[KeyGenerator] The provided switching key has invalid type.");
};

inline void checkModPackKeyBundleCondition(const deb::Context &context,
                                           const deb::Context &context_from,
                                           const deb::Context &context_to) {

    [[maybe_unused]] const deb::Size from_degree = context_from->get_degree();
    [[maybe_unused]] const deb::Size from_rank = context_from->get_rank();
    [[maybe_unused]] const deb::Size to_degree = context_to->get_degree();
    [[maybe_unused]] const deb::Size to_rank = context_to->get_rank();
    [[maybe_unused]] const deb::Size degree = context->get_degree();

    // check dimension is compatible
    // check output ctxt dimension could be resulted by a single key switching
    deb_assert(
        to_degree * to_rank == degree,
        "[genModPackKeyBundle] Total dimension of output secret key is not "
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

KeyGenerator::KeyGenerator(const Preset preset,
                           std::optional<const RNGSeed> seeds)
    : context_(getContext(preset)), sk_(std::nullopt),
      fft_(context_->get_degree()) {
    for (u64 i = 0; i < context_->get_num_p(); ++i) {
        modarith_.emplace_back(context_->get_degree(),
                               context_->get_primes()[i]);
    }
    if (!seeds) {
        seeds.emplace(SeedGenerator::Gen());
    }
    as_ = std::shared_ptr<void>(
        alea_init(to_alea_seed(seeds.value()), ALEA_ALGORITHM_SHAKE256),
        [](void *p) { alea_free(static_cast<alea_state *>(p)); });

    computeConst();
}

KeyGenerator::KeyGenerator(const SecretKey &sk,
                           std::optional<const RNGSeed> seeds)
    : KeyGenerator(sk.preset(), std::move(seeds)) {
    sk_ = sk;
}

void KeyGenerator::genSwitchingKey(const Polynomial *from, const Polynomial *to,
                                   Polynomial *ax, Polynomial *bx,
                                   const Size ax_size,
                                   const Size bx_size) const {
    const Size num_secret = context_->get_num_secret();
    const Size degree = context_->get_degree();
    const Size length = context_->get_num_base() + context_->get_num_qp();
    const Size max_length = context_->get_num_p();
    const Size dnum = context_->get_gadget_rank();
    const Size alpha = (length + dnum - 1) / dnum;
    Size a_size = ax_size == 0 ? dnum : ax_size;
    Size b_size = bx_size == 0 ? dnum * num_secret : bx_size;

    for (Size i = 0; i < a_size; ++i) {
        sampleUniform(ax[i]);
    }

    Polynomial tmp(context_, max_length);

    const Size s_size = b_size / a_size;
    for (Size idx = 0; idx < a_size; ++idx) {
        const auto &a = ax[idx];
        for (Size sid = 0; sid < s_size; ++sid) {
            auto &b = bx[idx + sid * a_size];
            auto ex = sampleGaussian(max_length, true);

            mulPoly(modarith_, a, to[sid], b);
            subPoly(modarith_, ex, b, b);

            for (Size tdx = 0; tdx < max_length; ++tdx) {
                if (tdx < idx * alpha ||
                    tdx >= std::min((idx + 1) * alpha, length)) {
                    for (Size i = 0; i < degree; ++i) {
                        tmp[tdx][i] = 0;
                    }
                }
            }
            constMulPoly(modarith_, from[sid], p_mod_.data(), tmp, idx * alpha,
                         std::min((idx + 1) * alpha, length));
            constMulPoly(modarith_, tmp, hat_q_i_mod_.data(), tmp, idx * alpha,
                         std::min((idx + 1) * alpha, length));
            // TODO: optimize inplace addition
            // addPoly(modarith_, b, tmp, b);
            // Polynomial tmp_copy(tmp, idx * alpha,
            //                     std::min(alpha, length - idx * alpha));
            // Polynomial b_copy(b, idx * alpha,
            //                   std::min(alpha, length - idx * alpha));
            // addPoly(modarith_, b_copy, tmp_copy, b_copy);
            addPoly(modarith_, b, tmp, b);
        }
    }
}

SwitchKey KeyGenerator::genEncKey(std::optional<SecretKey> sk) const {
    SwitchKey enckey(context_, SWK_ENC);
    genEncKeyInplace(enckey, sk);
    return enckey;
}

void KeyGenerator::genEncKeyInplace(SwitchKey &enckey,
                                    std::optional<SecretKey> sk) const {
    if (!sk.has_value())
        sk = sk_;
    checkSecretKey(context_, sk);
    checkSwk(context_, enckey, SWK_ENC);
    const bool ntt_state = true; // currently only support ntt state keys
    const Size num_poly = context_->get_num_p();
    const Size num_secret = context_->get_num_secret();
    deb_assert(enckey.bxSize() == num_secret && enckey.axSize() == 1,
               "[KeyGenerator::genEncKeyInplace] "
               "The provided switching key has invalid size.");

    sampleUniform(enckey.ax());
    auto ex = sampleGaussian(num_poly, ntt_state);

    for (Size i = 0; i < num_secret; ++i) {
        mulPoly(modarith_, enckey.ax(), (*sk)[i], enckey.bx(i));
        subPoly(modarith_, ex, enckey.bx(i), enckey.bx(i));
    }
}

SwitchKey KeyGenerator::genMultKey(std::optional<SecretKey> sk) const {
    SwitchKey mulkey(context_, SWK_MULT);
    genMultKeyInplace(mulkey, sk);
    return mulkey;
}

void KeyGenerator::genMultKeyInplace(SwitchKey &mulkey,
                                     std::optional<SecretKey> sk) const {
    if (!sk.has_value())
        sk = sk_;
    checkSecretKey(context_, sk);
    checkSwk(context_, mulkey, SWK_MULT);
    const bool ntt_state = true; // currently only support ntt state keys
    const Size num_secret = context_->get_num_secret();
    const Size max_length = context_->get_num_p();
    deb_assert(mulkey.bxSize() == num_secret * mulkey.dnum() &&
                   mulkey.axSize() == mulkey.dnum(),
               "[KeyGenerator::genMultKeyInplace] "
               "The provided switching key has invalid size.");

    std::vector<Polynomial> sx2;
    for (Size i = 0; i < num_secret; ++i) {
        sx2.emplace_back(context_, max_length);
        sx2[i].setNTT(ntt_state);

        mulPoly(modarith_, (*sk)[i], (*sk)[i], sx2[i]);
    }
    genSwitchingKey(sx2.data(), sk->data(), mulkey.getAx().data(),
                    mulkey.getBx().data());
}

SwitchKey KeyGenerator::genConjKey(std::optional<SecretKey> sk) const {
    SwitchKey conjkey(context_, SWK_CONJ);
    genConjKeyInplace(conjkey, sk);
    return conjkey;
}

void KeyGenerator::genConjKeyInplace(SwitchKey &conjkey,
                                     std::optional<SecretKey> sk) const {
    if (!sk.has_value())
        sk = sk_;
    checkSecretKey(context_, sk);
    checkSwk(context_, conjkey, SWK_CONJ);
    const bool ntt_state = (*sk)[0][0].isNTT();

    const Size num_secret = context_->get_num_secret();
    const Size max_length = context_->get_num_p();
    deb_assert(conjkey.bxSize() == num_secret * conjkey.dnum() &&
                   conjkey.axSize() == conjkey.dnum(),
               "[KeyGenerator::genConjKeyInplace] "
               "The provided switching key has invalid size.");

    std::vector<Polynomial> sx;
    for (Size i = 0; i < num_secret; ++i) {
        sx.emplace_back(context_, max_length);
        sx[i].setNTT(ntt_state);
        // frobenius map in NTT
        frobeniusMapInNTT((*sk)[i], -1, sx[i]);
    }

    genSwitchingKey(sx.data(), sk->data(), conjkey.getAx().data(),
                    conjkey.getBx().data());
}

SwitchKey KeyGenerator::genLeftRotKey(const Size rot,
                                      std::optional<SecretKey> sk) const {
    SwitchKey rotkey(context_, SWK_ROT);
    genLeftRotKeyInplace(rot, rotkey, sk);
    return rotkey;
}

void KeyGenerator::genLeftRotKeyInplace(const Size rot, SwitchKey &rotkey,
                                        std::optional<SecretKey> sk) const {
    if (!sk.has_value())
        sk = sk_;
    checkSecretKey(context_, sk);
    checkSwk(context_, rotkey, SWK_ROT);
    deb_assert(rot < context_->get_num_slots(),
               "[KeyGenerator::genLeftRotKeyInplace] "
               "Rotation value exceeds number of slots.");
    const auto ntt_state = true; // currently only support ntt state keys

    const Size num_secret = context_->get_num_secret();
    const Size max_length = context_->get_num_p();
    deb_assert(rotkey.bxSize() == num_secret * rotkey.dnum() &&
                   rotkey.axSize() == rotkey.dnum(),
               "[KeyGenerator::genLeftRotKeyInplace] "
               "The provided switching key has invalid size.");

    rotkey.setRotIdx(rot);

    std::vector<Polynomial> sx;
    for (Size i = 0; i < num_secret; ++i) {
        sx.emplace_back(context_, max_length);
        sx[i].setNTT(ntt_state);

        frobeniusMapInNTT((*sk)[i], static_cast<i32>(fft_.getPowerOfFive(rot)),
                          sx[i]);
    }
    genSwitchingKey(sx.data(), sk->data(), rotkey.getAx().data(),
                    rotkey.getBx().data());
}

SwitchKey KeyGenerator::genRightRotKey(const Size rot,
                                       std::optional<SecretKey> sk) const {
    const Size left_rot_id = context_->get_num_slots() - rot;
    SwitchKey rotkey(context_, SWK_ROT);
    genLeftRotKeyInplace(left_rot_id, rotkey, sk);
    return rotkey;
}

void KeyGenerator::genRightRotKeyInplace(const Size rot, SwitchKey &rotkey,
                                         std::optional<SecretKey> sk) const {
    genLeftRotKeyInplace(context_->get_num_slots() - rot, rotkey, sk);
}

SwitchKey KeyGenerator::genAutoKey(const Size sig,
                                   std::optional<SecretKey> sk) const {
    SwitchKey autokey(context_, SWK_AUTO);
    genAutoKeyInplace(sig, autokey, sk);
    return autokey;
}
void KeyGenerator::genAutoKeyInplace(const Size sig, SwitchKey &autokey,
                                     std::optional<SecretKey> sk) const {
    if (!sk.has_value())
        sk = sk_;
    checkSecretKey(context_, sk);
    checkSwk(context_, autokey, SWK_AUTO);
    deb_assert(sig < context_->get_degree(),
               "[KeyGenerator::genAutoKey] "
               "Signature value exceeds polynomial degree.");

    const Size num_secret = context_->get_num_secret();
    const Size degree = context_->get_degree();
    deb_assert(autokey.bxSize() == num_secret * autokey.dnum() &&
                   autokey.axSize() == autokey.dnum(),
               "[KeyGenerator::genAutoKey] "
               "The provided switching key has invalid size.");
    autokey.setRotIdx(sig);

    std::vector<i8> coeff_sig(degree);

    automorphism(sk->coeffs(), coeff_sig.data(), sig, degree);
    SecretKey sk_sig = SecretKeyGenerator::GenSecretKeyFromCoeff(
        context_->get_preset(), coeff_sig.data());
    genSwitchingKey(sk_sig.data(), sk->data(), autokey.getAx().data(),
                    autokey.getBx().data());
}

SwitchKey KeyGenerator::genComposeKey(const SecretKey &sk_from,
                                      std::optional<SecretKey> sk) const {
    // TODO: check prime compatibility
    return genComposeKey(sk_from.coeffs(), sk_from.coeffsSize(), sk);
}
SwitchKey KeyGenerator::genComposeKey(const std::vector<i8> coeffs,
                                      std::optional<SecretKey> sk) const {
    return genComposeKey(coeffs.data(), static_cast<Size>(coeffs.size()), sk);
}
SwitchKey KeyGenerator::genComposeKey(const i8 *coeffs, const Size coeffs_size,
                                      std::optional<SecretKey> sk) const {
    SwitchKey composekey(context_, SWK_COMPOSE);
    genComposeKeyInplace(coeffs, coeffs_size, composekey, sk);
    return composekey;
}

void KeyGenerator::genComposeKeyInplace(const SecretKey &sk_from,
                                        SwitchKey &composekey,
                                        std::optional<SecretKey> sk) const {
    genComposeKeyInplace(sk_from.coeffs(), sk_from.coeffsSize(), composekey,
                         sk);
}
void KeyGenerator::genComposeKeyInplace(const std::vector<i8> coeffs,
                                        SwitchKey &composekey,
                                        std::optional<SecretKey> sk) const {
    genComposeKeyInplace(coeffs.data(), static_cast<Size>(coeffs.size()),
                         composekey, sk);
}
void KeyGenerator::genComposeKeyInplace(const i8 *coeffs,
                                        const Size coeffs_size,
                                        SwitchKey &composekey,
                                        std::optional<SecretKey> sk) const {
    if (!sk.has_value())
        sk = sk_;
    checkSecretKey(context_, sk);
    checkSwk(context_, composekey, SWK_COMPOSE);

    const Size num_secret = context_->get_num_secret();
    const Size deg_ratio = context_->get_degree() / coeffs_size;
    deb_assert(coeffs_size * deg_ratio == context_->get_degree(),
               "[KeyGenerator::genComposeKey] "
               "The provided secret key has invalid size.");
    deb_assert(composekey.bxSize() == num_secret * composekey.dnum() &&
                   composekey.axSize() == composekey.dnum(),
               "[KeyGenerator::genComposeKeyInplace] "
               "The provided switching key has invalid size.");

    std::vector<i8> coeffs_embed(context_->get_degree(), 0);
    for (Size i = 0; i < coeffs_size; ++i) {
        coeffs_embed[i * deg_ratio] = coeffs[i];
    }
    SecretKey sk_from = SecretKeyGenerator::GenSecretKeyFromCoeff(
        context_->get_preset(), coeffs_embed.data());

    genSwitchingKey(sk_from.data(), sk->data(), composekey.getAx().data(),
                    composekey.getBx().data());
}

SwitchKey KeyGenerator::genDecomposeKey(const SecretKey &sk_to,
                                        std::optional<SecretKey> sk) const {
    return genDecomposeKey(sk_to.coeffs(), sk_to.coeffsSize(), sk);
}
SwitchKey KeyGenerator::genDecomposeKey(const std::vector<i8> coeffs,
                                        std::optional<SecretKey> sk) const {
    return genDecomposeKey(coeffs.data(), static_cast<Size>(coeffs.size()), sk);
}
SwitchKey KeyGenerator::genDecomposeKey(const i8 *coeffs,
                                        const Size coeffs_size,
                                        std::optional<SecretKey> sk) const {
    SwitchKey decompkey(context_, SWK_DECOMPOSE);
    genDecomposeKeyInplace(coeffs, coeffs_size, decompkey, sk);

    return decompkey;
}

void KeyGenerator::genDecomposeKeyInplace(const SecretKey &sk_to,
                                          SwitchKey &decompkey,
                                          std::optional<SecretKey> sk) const {
    genDecomposeKeyInplace(sk_to.coeffs(), sk_to.coeffsSize(), decompkey, sk);
}
void KeyGenerator::genDecomposeKeyInplace(const std::vector<i8> coeffs,
                                          SwitchKey &decompkey,
                                          std::optional<SecretKey> sk) const {
    genDecomposeKeyInplace(coeffs.data(), static_cast<Size>(coeffs.size()),
                           decompkey, sk);
}
void KeyGenerator::genDecomposeKeyInplace(const i8 *coeffs,
                                          const Size coeffs_size,
                                          SwitchKey &decompkey,
                                          std::optional<SecretKey> sk) const {
    if (!sk.has_value())
        sk = sk_;
    checkSecretKey(context_, sk);
    checkSwk(context_, decompkey, SWK_DECOMPOSE);
    const Size num_secret = context_->get_num_secret();
    const Size deg_ratio = context_->get_degree() / coeffs_size;
    deb_assert(coeffs_size * deg_ratio == context_->get_degree(),
               "[KeyGenerator::genDecomposeKey] "
               "The provided secret key has invalid size.");

    deb_assert(decompkey.bxSize() == num_secret * decompkey.dnum() &&
                   decompkey.axSize() == decompkey.dnum(),
               "[KeyGenerator::genDecomposeKeyInplace] "
               "The provided switching key has invalid size.");

    std::vector<i8> coeffs_embed(context_->get_degree(), 0);
    for (Size i = 0; i < coeffs_size; ++i) {
        coeffs_embed[i * deg_ratio] = coeffs[i];
    }
    SecretKey sk_to = SecretKeyGenerator::GenSecretKeyFromCoeff(
        context_->get_preset(), coeffs_embed.data());
    genSwitchingKey(sk->data(), sk_to.data(), decompkey.getAx().data(),
                    decompkey.getBx().data());
}

SwitchKey KeyGenerator::genDecomposeKey(const Preset preset_swk,
                                        const SecretKey &sk_to,
                                        std::optional<SecretKey> sk) const {
    return genDecomposeKey(preset_swk, sk_to.coeffs(), sk_to.coeffsSize(), sk);
}
SwitchKey KeyGenerator::genDecomposeKey(const Preset preset_swk,
                                        const std::vector<i8> coeffs,
                                        std::optional<SecretKey> sk) const {
    return genDecomposeKey(preset_swk, coeffs.data(),
                           static_cast<Size>(coeffs.size()), sk);
}
SwitchKey KeyGenerator::genDecomposeKey(const Preset preset_swk,
                                        const i8 *coeffs, Size coeffs_size,
                                        std::optional<SecretKey> sk) const {
    Context context_swk = getContext(preset_swk);
    SwitchKey decompkey(context_swk, SWK_DECOMPOSE);
    genDecomposeKeyInplace(preset_swk, coeffs, coeffs_size, decompkey, sk);
    return decompkey;
}
void KeyGenerator::genDecomposeKeyInplace(const Preset preset_swk,
                                          const SecretKey &sk_to,
                                          SwitchKey &decompkey,
                                          std::optional<SecretKey> sk) const {
    genDecomposeKeyInplace(preset_swk, sk_to.coeffs(), sk_to.coeffsSize(),
                           decompkey, sk);
}
void KeyGenerator::genDecomposeKeyInplace(const Preset preset_swk,
                                          const std::vector<i8> coeffs,
                                          SwitchKey &decompkey,
                                          std::optional<SecretKey> sk) const {
    genDecomposeKeyInplace(preset_swk, coeffs.data(),
                           static_cast<Size>(coeffs.size()), decompkey, sk);
}
void KeyGenerator::genDecomposeKeyInplace(const Preset preset_swk,
                                          const i8 *coeffs, Size coeffs_size,
                                          SwitchKey &decompkey,
                                          std::optional<SecretKey> sk) const {
    if (!sk.has_value())
        sk = sk_;
    Context context_swk = getContext(preset_swk);
    checkSecretKey(context_, sk);
    checkSwk(context_swk, decompkey, SWK_DECOMPOSE);
    deb_assert(
        context_->get_degree() == context_swk->get_degree(),
        "[KeyGenerator::genDecomposeKey] "
        "Degree mismatch between KeyGenerator and switching key preset.");

    const Size num_secret = context_swk->get_num_secret();
    const Size deg_ratio = context_swk->get_degree() / coeffs_size;
    deb_assert(coeffs_size * deg_ratio == context_->get_degree(),
               "[KeyGenerator::genDecomposeKey] "
               "The provided secret key has invalid size.");
    deb_assert(decompkey.bxSize() == num_secret * decompkey.dnum() &&
                   decompkey.axSize() == decompkey.dnum(),
               "[KeyGenerator::genDecomposeKeyInplace] "
               "The provided switching key has invalid size.");

    std::vector<i8> coeffs_embed(context_->get_degree(), 0);
    for (Size i = 0; i < coeffs_size; ++i) {
        coeffs_embed[i * deg_ratio] = coeffs[i];
    }
    SecretKey sk_to = SecretKeyGenerator::GenSecretKeyFromCoeff(
        context_swk->get_preset(), coeffs_embed.data());
    SecretKey sk_from = SecretKeyGenerator::GenSecretKeyFromCoeff(
        context_swk->get_preset(), sk->coeffs());
    KeyGenerator keygen_swk(preset_swk);
    keygen_swk.genSwitchingKey(sk_from.data(), sk_to.data(),
                               decompkey.getAx().data(),
                               decompkey.getBx().data());
}

std::vector<SwitchKey>
KeyGenerator::genModPackKeyBundle(const SecretKey &sk_from,
                                  const SecretKey &sk_to) const {
    std::vector<SwitchKey> key_bundle;
    const auto num_key = getContext(sk_from.preset())->get_rank() /
                         getContext(sk_to.preset())->get_rank();
    for (u64 i = 0; i < num_key; ++i) {
        key_bundle.emplace_back(context_, SWK_MODPACK);
    }

    genModPackKeyBundleInplace(sk_from, sk_to, key_bundle);
    return key_bundle;
}

void KeyGenerator::genModPackKeyBundleInplace(
    const SecretKey &sk_from, const SecretKey &sk_to,
    std::vector<SwitchKey> &key_bundle) const {
    deb_assert(sk_from[0][0].isNTT() == sk_to[0][0].isNTT(),
               "[KeyGenerator::genModPackKeyBundle] "
               "NTT state mismatch between input secret keys.");

    const auto context_from = getContext(sk_from.preset());
    const auto context_to = getContext(sk_to.preset());
    checkModPackKeyBundleCondition(context_, context_from, context_to);

    [[maybe_unused]] const Size num_secret = context_->get_num_secret();
    const u64 from_deg = context_from->get_degree();
    const u64 from_rank = context_from->get_rank();
    const u64 to_deg = context_to->get_degree();
    const u64 to_rank = context_to->get_rank();
    const u64 rlwe_deg = context_->get_degree();
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

    SecretKey sk_to_rlwe = SecretKeyGenerator::GenSecretKeyFromCoeff(
        context_->get_preset(), rlwe_coeff);

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
        SecretKey sk_from_rlwe = SecretKeyGenerator::GenSecretKeyFromCoeff(
            context_->get_preset(), rlwe_coeff);
        genSwitchingKey(sk_from_rlwe.data(), sk_to_rlwe.data(),
                        key_bundle[i].getAx().data(),
                        key_bundle[i].getBx().data());
    }
    delete[] rlwe_coeff;
}

SwitchKey KeyGenerator::genModPackKeyBundle(const Size pad_rank,
                                            std::optional<SecretKey> sk) const {
    SwitchKey modkey(context_, SWK_MODPACK_SELF);
    const auto max_length = context_->get_num_p();
    modkey.addAx(max_length, pad_rank, true);
    modkey.addBx(max_length, pad_rank * context_->get_num_secret(), true);
    genModPackKeyBundleInplace(pad_rank, modkey, sk);
    return modkey;
}
void KeyGenerator::genModPackKeyBundleInplace(
    const Size pad_rank, SwitchKey &modkey, std::optional<SecretKey> sk) const {
    if (!sk.has_value())
        sk = sk_;
    checkSecretKey(context_, sk);
    checkSwk(context_, modkey, SWK_MODPACK_SELF);
    const Size items_per_ctxt = context_->get_degree() / pad_rank;
    const Size degree = context_->get_degree();
    deb_assert(
        utils::isPowerOfTwo(pad_rank),
        "[KeyGenerator::genModPackKeyBundle] pad_rank must be a power of two.");
    deb_assert(modkey.bxSize() == pad_rank * context_->get_num_secret() &&
                   modkey.axSize() == pad_rank,
               "[KeyGenerator::genModPackKeyBundle] The provided switching key "
               "has invalid size.");

    for (Size i = 0; i < pad_rank; ++i) {
        auto *from_coeff = new i8[degree];
        std::memset(from_coeff, 0, degree);
        for (Size j = 0; j < items_per_ctxt; ++j) {
            from_coeff[pad_rank * j] =
                sk->coeffs()[j * pad_rank + pad_rank - 1 - i];
        }
        SecretKey sk_from =
            SecretKeyGenerator::GenSecretKeyFromCoeff(sk->preset(), from_coeff);
        genSwitchingKey(sk_from.data(), sk->data(), &(modkey.ax(i)),
                        &(modkey.bx(i)), 1, context_->get_num_secret());
        delete[] from_coeff;
    }
}

void KeyGenerator::frobeniusMapInNTT(const Polynomial &op, const i32 pow,
                                     Polynomial res) const {
    deb_assert(op[0].isNTT(), "[KeyGenerator::frobeniusMapInNTT] "
                              "Input polynomial must be in NTT state.");
    deb_assert(pow % 2 != 0, "[KeyGenerator::frobeniusMapInNTT] "
                             "Frobenius map power must be odd.");

    Size degree = context_->get_degree();
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

Polynomial KeyGenerator::sampleGaussian(const Size num_polyunit,
                                        bool do_ntt) const {
    const auto degree = context_->get_degree();
    std::vector<i64> samples(degree);
    alea_sample_gaussian_int64_array(as_.get(), samples.data(), degree,
                                     context_->get_gaussian_error_stdev());
    Polynomial poly(context_, num_polyunit);
    for (Size i = 0; i < poly.size(); ++i) {
        poly[i].setPrime(context_->get_primes()[i]);
        for (Size j = 0; j < context_->get_degree(); ++j) {
            // Convert int64_t sample to u64
            poly[i][j] = (samples[j] >= 0) ? static_cast<u64>(samples[j])
                                           : context_->get_primes()[i] -
                                                 static_cast<u64>(-samples[j]);
        }
    }

    if (do_ntt) {
        forwardNTT(modarith_, poly);
    }
    return poly;
}

void KeyGenerator::sampleUniform(Polynomial &poly) const {
    // TODO: add reseed controller
    for (u64 i = 0; i < poly.size(); ++i) {
        alea_get_random_uint64_array_in_range(
            as_.get(), poly[i].data(), context_->get_degree(), poly[i].prime());
    }
}

void KeyGenerator::computeConst() {
    const Size length = context_->get_num_base() + context_->get_num_qp();
    const Size dnum = context_->get_gadget_rank();
    const Size alpha = (length + dnum - 1) / dnum;

    p_mod_.resize(length);
    for (Size i = 0; i < length; ++i) {
        const u64 prime = context_->get_primes()[i];
        const u64 two_prime = prime << 1;
        u64 p = UINT64_C(1);

        for (Size j = 0; j < context_->get_num_tp(); ++j) {
            const u64 pp = modarith_[i].reduceBarrett<2>(
                context_->get_primes()[j + length]);
            p = modarith_[i].mul(p, pp);
        }
        p = utils::subIfGE(p, two_prime);
        p_mod_[i] = utils::subIfGE(p, prime);
    }

    hat_q_i_mod_.resize(length);
    hat_q_i_inv_mod_.resize(length);

    for (Size i = 0; i < length; ++i) {
        const u64 beta = i / alpha;
        const u64 prime = context_->get_primes()[i];
        const u64 two_prime = prime << 1;
        u64 hat_q = UINT64_C(1);

        for (Size j = 0; j < length; ++j) {
            if (j < beta * alpha || j >= (beta + 1) * alpha) {
                u64 pp =
                    modarith_[i].reduceBarrett<2>(context_->get_primes()[j]);
                hat_q = modarith_[i].mul(hat_q, pp);
            }
        }

        hat_q = utils::subIfGE(hat_q, two_prime);
        hat_q = utils::subIfGE(hat_q, prime);

        hat_q_i_mod_[i] = hat_q;
        hat_q_i_inv_mod_[i] = modarith_[i].inverse(hat_q);
    }
}
} // namespace deb
