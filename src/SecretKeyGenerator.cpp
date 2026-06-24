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

#include "SecretKeyGenerator.hpp"

namespace deb {

template <typename U>
SecretKeyGeneratorT<U>::SecretKeyGeneratorT(Preset preset) : preset_(preset) {}

template <typename U>
SecretKeyT<U>
SecretKeyGeneratorT<U>::genSecretKey(std::optional<const RNGSeed> seed,
                                     utils::NTTType ntt_type) {
    return GenSecretKey(preset_, seed, ntt_type);
}

template <typename U>
void SecretKeyGeneratorT<U>::genSecretKeyInplace(
    SecretKeyT<U> &sk, std::optional<const RNGSeed> seed,
    utils::NTTType ntt_type) {
    GenSecretKeyInplace(sk, seed, ntt_type);
}

template <typename U>
SecretKeyT<U>
SecretKeyGeneratorT<U>::genSecretKeyFromCoeff(const i8 *coeffs,
                                              utils::NTTType ntt_type) {
    return GenSecretKeyFromCoeff(preset_, coeffs, ntt_type);
}

template <typename U>
void SecretKeyGeneratorT<U>::genSecretKeyFromCoeffInplace(
    SecretKeyT<U> &sk, const i8 *coeffs, utils::NTTType ntt_type) {
    GenSecretKeyFromCoeffInplace(sk, coeffs, ntt_type);
}

template <typename U>
i8 *SecretKeyGeneratorT<U>::GenCoeff(const Preset preset, const RNGSeed seed) {
    const auto dim = get_degree(preset);
    const auto num_secret = get_num_secret(preset);
    const auto section_size = get_rank(preset) * dim;
    const auto size = section_size * num_secret;
    i8 *coeffs = new i8[size];
    GenCoeffInplace(preset, coeffs, seed);
    return coeffs;
}

template <typename U>
RNGSeed
SecretKeyGeneratorT<U>::GenCoeffInplace(const Preset preset, i8 *coeffs,
                                        std::optional<const RNGSeed> seed) {
    const auto dim = get_degree(preset);
    const auto num_secret = get_num_secret(preset);
    const auto section_size = get_rank(preset) * dim;

    if (!seed) {
        seed.emplace(SeedGenerator::Gen());
    }
    auto rng = createRandomGenerator(seed.value());
    for (Size i = 0; i < num_secret; ++i) {
        rng->sampleHwtInt8Array(coeffs + i * section_size, section_size,
                                static_cast<int>(get_hamming_weight(preset)));
    }
    return seed.value();
}

template <typename U>
SecretKeyT<U>
SecretKeyGeneratorT<U>::ComputeEmbedding(const Preset preset, const i8 *coeffs,
                                         std::optional<Size> level,
                                         utils::NTTType ntt_type) {
    level = level.value_or(get_num_p(preset) - 1);
    SecretKeyT<U> sk(preset);
    sk.allocPolys(level.value() + 1);
    ComputeEmbeddingInplace(sk, coeffs, ntt_type);
    return sk;
}

template <typename U>
void SecretKeyGeneratorT<U>::ComputeEmbeddingInplace(SecretKeyT<U> &sk,
                                                     const i8 *coeffs,
                                                     utils::NTTType ntt_type) {
    const auto dim = get_degree(sk.preset());
    const auto num_secret = get_num_secret(sk.preset());
    const auto rank = get_rank(sk.preset());

    deb_assert(
        coeffs != nullptr,
        "[SecretKeyGeneratorT::ComputeEmbeddingInplace] Coefficients are "
        "not allocated.");
    if (sk.coeffs() != coeffs) {
        sk.allocCoeffs();
        memcpy(sk.coeffs(), coeffs, rank * dim * num_secret * sizeof(i8));
    }

    if (sk.numPoly() != rank * num_secret) {
        sk.allocPolys();
    }
    for (Size i = 0; i < rank * num_secret; ++i) {
        for (Size j = 0; j < sk[i].size(); ++j) {
            U *ptr = sk[i][j].data();
            const u64 prime_j = get_primes(sk.preset())[j];
            for (Size k = 0; k < dim; ++k) {
                const i8 c = sk.coeffs()[i * dim + k];
                ptr[k] = (c >= 0)
                             ? static_cast<U>(c)
                             : static_cast<U>(prime_j - static_cast<u64>(-c));
            }
            // TODO: reuse NTT object
            auto ntt = utils::createNTT<U>(dim, prime_j, ntt_type,
                                           utils::getGlobalNTTRootType());
            ntt->computeForward(sk[i][j].data());
            sk[i][j].setNTT(ntt_type, utils::getGlobalNTTRootType());
        }
    }
}

template <typename U>
SecretKeyT<U> SecretKeyGeneratorT<U>::GenSecretKey(
    Preset preset, std::optional<const RNGSeed> seed, utils::NTTType ntt_type) {
    SecretKeyT<U> sk(preset);
    sk.setSeed(GenCoeffInplace(preset, sk.coeffs(), seed));
    GenSecretKeyFromCoeffInplace(sk, sk.coeffs(), ntt_type);
    return sk;
}

template <typename U>
void SecretKeyGeneratorT<U>::GenSecretKeyInplace(
    SecretKeyT<U> &sk, std::optional<const RNGSeed> seed,
    utils::NTTType ntt_type) {
    sk.setSeed(GenCoeffInplace(sk.preset(), sk.coeffs(), seed));
    GenSecretKeyFromCoeffInplace(sk, sk.coeffs(), ntt_type);
}

template <typename U>
SecretKeyT<U> SecretKeyGeneratorT<U>::GenSecretKeyFromCoeff(
    const Preset preset, const i8 *coeffs, utils::NTTType ntt_type) {
    SecretKeyT<U> sk(preset);
    GenSecretKeyFromCoeffInplace(sk, coeffs, ntt_type);
    return sk;
}

template <typename U>
void SecretKeyGeneratorT<U>::GenSecretKeyFromCoeffInplace(
    SecretKeyT<U> &sk, const i8 *coeffs, utils::NTTType ntt_type) {
    ComputeEmbeddingInplace(sk, coeffs, ntt_type);
}

template <typename U>
void completeSecretKey(SecretKeyT<U> &sk, std::optional<Size> level,
                       utils::NTTType ntt_type) {
    const auto rank = get_rank(sk.preset());
    const auto num_secret = get_num_secret(sk.preset());
    const auto degree = get_degree(sk.preset());
    if (sk.coeffsSize() != rank * num_secret * degree) {
        sk.allocCoeffs();
        if (!sk.hasSeed()) {
            throw std::runtime_error(
                "[completeSecretKey] Secret key has no seed.");
        }
        SecretKeyGeneratorT<U>::GenCoeffInplace(sk.preset(), sk.coeffs(),
                                                sk.getSeed());
    }
    level = level.value_or(get_num_p(sk.preset()) - 1);
    if (sk.numPoly() != num_secret * rank ||
        sk[0].size() != level.value() + 1) {
        sk.allocPolys(level.value() + 1);
    }
    SecretKeyGeneratorT<U>::ComputeEmbeddingInplace(sk, sk.coeffs(), ntt_type);
}

// Explicit instantiations
#ifdef DEB_U64
template class SecretKeyGeneratorT<u64>;
template void completeSecretKey<u64>(SecretKeyT<u64> &, std::optional<Size>,
                                     utils::NTTType);
#endif

#ifdef DEB_U32
template class SecretKeyGeneratorT<u32>;
template void completeSecretKey<u32>(SecretKeyT<u32> &, std::optional<Size>,
                                     utils::NTTType);
#endif

} // namespace deb
