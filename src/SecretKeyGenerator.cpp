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

#include "SecretKeyGenerator.hpp"
#include "Serialize.hpp"

namespace deb {

SecretKeyGenerator::SecretKeyGenerator(Preset preset) : preset_(preset) {}

SecretKey SecretKeyGenerator::genSecretKey(std::optional<const RNGSeed> seeds) {
    return GenSecretKey(preset_, seeds);
}

void SecretKeyGenerator::genSecretKeyInplace(
    SecretKey &sk, std::optional<const RNGSeed> seeds) {
    GenSecretKeyInplace(sk, seeds);
}

SecretKey SecretKeyGenerator::genSecretKeyFromCoeff(const i8 *coeffs) {
    return GenSecretKeyFromCoeff(preset_, coeffs);
}

void SecretKeyGenerator::genSecretKeyFromCoeffInplace(SecretKey &sk,
                                                      const i8 *coeffs) {
    GenSecretKeyFromCoeffInplace(sk, coeffs);
}

i8 *SecretKeyGenerator::GenCoeff(const Preset preset, const RNGSeed seed) {
    const auto context = getContext(preset);
    const auto dim = context->get_degree();
    const auto num_secret = context->get_num_secret();
    const auto section_size = context->get_rank() * dim;
    const auto size = section_size * num_secret;
    i8 *coeffs = new i8[size];
    GenCoeffInplace(preset, coeffs, seed);
    return coeffs;
}

RNGSeed SecretKeyGenerator::GenCoeffInplace(const Preset preset, i8 *coeffs,
                                            std::optional<const RNGSeed> seed) {
    const auto context = getContext(preset);
    const auto dim = context->get_degree();
    const auto num_secret = context->get_num_secret();
    const auto section_size = context->get_rank() * dim;

    if (!seed) {
        seed.emplace(SeedGenerator::Gen());
    }
    alea_state *as = alea_init(reinterpret_cast<const u8 *>(seed->data()),
                               ALEA_ALGORITHM_SHAKE256);
    // Sample Hamming weight
    for (Size i = 0; i < num_secret; ++i) {
        alea_sample_hwt_int8_array(
            as, coeffs + i * section_size, section_size,
            static_cast<int>(context->get_hamming_weight()));
    }
    alea_free(as);
    return seed.value();
}

SecretKey SecretKeyGenerator::ComputeEmbedding(const Preset preset,
                                               const i8 *coeffs,
                                               std::optional<Size> level) {
    level = level.value_or(getContext(preset)->get_num_p() - 1);
    SecretKey sk(preset);
    sk.allocPolys(level.value() + 1);
    ComputeEmbeddingInplace(sk, coeffs);
    return sk;
}

void SecretKeyGenerator::ComputeEmbeddingInplace(SecretKey &sk,
                                                 const i8 *coeffs) {
    const auto context = getContext(sk.preset());
    const auto dim = context->get_degree();
    const auto num_secret = context->get_num_secret();
    const auto rank = context->get_rank();
    const auto section_size = rank * dim;

    deb_assert(coeffs != nullptr,
               "[SecretKeyGenerator::ComputeEmbeddingInplace] Coefficients are "
               "not allocated.");
    if (sk.coeffs() != coeffs) {
        sk.allocCoeffs();
        memcpy(sk.coeffs(), coeffs, section_size * num_secret * sizeof(i8));
    }

    if (sk.numPoly() != num_secret * rank) {
        sk.allocPolys();
    }
    for (Size ns_id = 0; ns_id < num_secret; ++ns_id) {
        for (Size i = 0; i < rank; ++i) {
            const Size idx = ns_id * rank + i;
            for (Size j = 0; j < sk[idx].size(); ++j) {
                u64 *ptr = sk[idx][j].data();
                for (Size k = 0; k < dim; ++k) {
                    ptr[k] =
                        (sk.coeffs()[i * dim + k] >= 0)
                            ? static_cast<u64>(sk.coeffs()[i * dim + k])
                            : context->get_primes()[j] -
                                  static_cast<u64>(-sk.coeffs()[i * dim + k]);
                }
                // TODO: reuse NTT object
                utils::NTT ntt(context->get_degree(), context->get_primes()[j]);
                ntt.computeForward(sk[idx][j].data());
                sk[idx][j].setNTT(true);
            }
        }
    }
}

SecretKey SecretKeyGenerator::GenSecretKey(Preset preset,
                                           std::optional<const RNGSeed> seeds) {
    SecretKey sk(preset);
    sk.setSeed(GenCoeffInplace(preset, sk.coeffs(), seeds));
    GenSecretKeyFromCoeffInplace(sk, sk.coeffs());
    return sk;
}

void SecretKeyGenerator::GenSecretKeyInplace(
    SecretKey &sk, std::optional<const RNGSeed> seeds) {
    sk.setSeed(GenCoeffInplace(sk.preset(), sk.coeffs(), seeds));
    GenSecretKeyFromCoeffInplace(sk, sk.coeffs());
}

SecretKey SecretKeyGenerator::GenSecretKeyFromCoeff(const Preset preset,
                                                    const i8 *coeffs) {

    SecretKey sk(preset);
    GenSecretKeyFromCoeffInplace(sk, coeffs);
    return sk;
}

void SecretKeyGenerator::GenSecretKeyFromCoeffInplace(SecretKey &sk,
                                                      const i8 *coeffs) {
    ComputeEmbeddingInplace(sk, coeffs);
}

void completeSecretKey(SecretKey &sk, std::optional<Size> level) {
    const auto context = getContext(sk.preset());
    const auto rank = context->get_rank();
    const auto num_secret = context->get_num_secret();
    const auto degree = context->get_degree();
    if (sk.coeffsSize() != rank * num_secret * degree) {
        sk.allocCoeffs();
        if (!sk.hasSeed()) {
            throw std::runtime_error(
                "[completeSecretKey] Secret key has no seed.");
        }
        SecretKeyGenerator::GenCoeffInplace(context->get_preset(), sk.coeffs(),
                                            sk.getSeed());
    }
    level = level.value_or(context->get_num_p() - 1);
    if (sk.numPoly() != num_secret * rank ||
        sk[0].size() != level.value() + 1) {
        sk.allocPolys(level.value() + 1);
    }
    SecretKeyGenerator::ComputeEmbeddingInplace(sk, sk.coeffs());
}
} // namespace deb
