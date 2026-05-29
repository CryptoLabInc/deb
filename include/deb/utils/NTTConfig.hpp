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

#include "Types.hpp"

namespace deb::utils {
/**
 * @brief Selects the transform type used when constructing an NTT.
 *
 *  - NONNTT:     Non NTT state. No forward NTT is applied.
 *
 *  - NEGACYCLIC: Computes polynomial multiplication modulo X^N + 1.
 *                Requires prime ≡ 1 mod 2·degree.  Uses a primitive 2N-th
 *                root of unity (psi) throughout.
 *
 *  - CYCLIC:     Computes polynomial multiplication modulo X^N + 1.
 *                Also requires prime ≡ 1 mod 4·degree.
 */
enum class NTTType : int { NONNTT = 0, NEGACYCLIC = 1, CYCLIC = 2 };

/**
 * @brief Selects the primitive-root algorithm used when constructing an NTT.
 *
 *  - MIN:    finds the global primitive root of (Z/pZ)* and then selects
 *            the smallest primitive 2N-th root of unity among all conjugates.
 *  - DIRECT: derives the primitive 2N-th root directly from the 2-adic
 *            structure of (p-1) without min-root selection.
 *  - CUSTOM: the user supplies the primitive 2N-th root of unity via
 *            registerCustomPsi() before constructing the NTT object.
 *            This applies to both NEGACYCLIC and CYCLIC transform types.
 */
enum class NTTRootType : int { MIN = 0, DIRECT = 1, CUSTOM = 2 };

/**
 * @brief Sets the global NTT root-finding algorithm.
 */
void setGlobalNTTRootType(NTTRootType type);

/**
 * @brief Returns the currently active global NTT root-finding algorithm.
 */
NTTRootType getGlobalNTTRootType();

/**
 * @brief RAII guard that temporarily changes the global NTT root type and
 *        restores the previous value on destruction.
 */
class ScopedNTTRootType {
public:
    explicit ScopedNTTRootType(NTTRootType type)
        : prev_(getGlobalNTTRootType()) {
        setGlobalNTTRootType(type);
    }
    ~ScopedNTTRootType() { setGlobalNTTRootType(prev_); }

    ScopedNTTRootType(const ScopedNTTRootType &) = delete;
    ScopedNTTRootType &operator=(const ScopedNTTRootType &) = delete;

private:
    NTTRootType prev_;
};

/**
 * @brief Registers a custom primitive root of unity for use with
 *        NTTRootType::CUSTOM.
 *
 * For the negacyclic NTT (`NTT<U>`), call with `(degree, prime, psi)` where
 * psi is a primitive 2·degree-th root of unity.
 *
 * For the cyclic NTT (`NTT_C<U>`), call with `(2*degree, prime, zeta)` where
 * zeta is a primitive 4·degree-th root of unity (the doubled key avoids
 * collision with the negacyclic entry for the same (degree, prime)).
 *
 * The function validates that psi^(2*degree) ≡ 1 and psi^degree ≢ 1
 * (mod prime) before storing it.  Thread-safe.
 */
void registerCustomPsi(u64 degree, u64 prime, u64 psi);

namespace detail {
// Looks up a CUSTOM psi from the global registry. registry_key_degree is the
// key stored by registerCustomPsi() — NEGACYCLIC uses (degree, prime), CYCLIC
// uses (2*degree, prime). Throws std::runtime_error if missing.
u64 lookupCustomPsi(u64 registry_key_degree, u64 prime, const char *ctx);
} // namespace detail

} // namespace deb::utils
