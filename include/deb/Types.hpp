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

#pragma once
#include <cstdint>

namespace deb {

/**
 * @brief Floating-point type used for high-precision real numbers.
 */
using Real = double;
#ifdef INT8_MAX
/**
 * @brief Signed 8-bit integer alias that maps to the native int8_t when
 * available.
 */
using i8 = int8_t;
/**
 * @brief Unsigned 8-bit integer alias that maps to the native uint8_t when
 * available.
 */
using u8 = uint8_t;
#else
/**
 * @brief Signed 8-bit integer alias that falls back to the least 8-bit type on
 * platforms without int8_t.
 */
using i8 = int_least8_t;
/**
 * @brief Unsigned 8-bit integer alias that falls back to the least 8-bit type
 * on platforms without uint8_t.
 */
using u8 = uint_least8_t;
#endif
/**
 * @brief Signed 32-bit integer alias used for indexing and polynomial degree
 * calculations.
 */
using i32 = int32_t;
/**
 * @brief Signed 64-bit integer alias used for accumulator style integer math.
 */
using i64 = int64_t;
/**
 * @brief Unsigned 32-bit integer alias used for modular arithmetic inputs.
 */
using u32 = uint32_t;
/**
 * @brief Unsigned 64-bit integer alias used for prime moduli and word slices.
 */
using u64 = uint64_t;
/**
 * @brief Default size type for slots, coefficients, and vector dimensions.
 */
using Size = uint32_t;

/**
 * @brief Identifies how plaintext data is interpreted when encoding or
 * decoding.
 */
enum EncodingType {
    UNKNOWN, /**< No encoding context is available. */
    COEFF,   /**< Data is treated as coefficient representation. */
    SLOT,    /**< Data is treated as slot/complex representation. */
};

/**
 * @brief Enumerates the supported switching key categories used in key
 * management APIs.
 */
enum SwitchKeyKind {
    SWK_GENERIC,      /**< Generic switch key with unspecified behavior. */
    SWK_ENC,          /**< Public encryption key. */
    SWK_MULT,         /**< Key for ciphertext-ciphertext multiplication. */
    SWK_ROT,          /**< Rotation key for cyclic slot shifts. */
    SWK_CONJ,         /**< Key that performs conjugation. */
    SWK_AUTO,         /**< Automorphism key indexed by signature. */
    SWK_COMPOSE,      /**< Key for composition into higher degree ring. */
    SWK_DECOMPOSE,    /**< Key for decomposition into lower degree ring. */
    SWK_MODPACK,      /**< Modulus switching key bundle. */
    SWK_MODPACK_SELF, /**< Modulus switching key for self-pack variants. */
};

} // namespace deb
