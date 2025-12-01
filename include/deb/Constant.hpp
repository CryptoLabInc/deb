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

#include "CKKSTypes.hpp"

namespace deb {

/**
 * @brief Maximum representable value for @ref Size within this library.
 */
constexpr Size DEB_MAX_SIZE = 4294967295;

/**
 * @brief Constant zero value for @ref Real computations.
 */
constexpr Real REAL_ZERO = 0.0;

/**
 * @brief Constant one value for @ref Real computations.
 */
constexpr Real REAL_ONE = 1.0;

/**
 * @brief Archimedes' constant used in FFT/CKKS calculations.
 */
constexpr Real REAL_PI = 3.14159265358979323846;

/**
 * @brief Two pi constant (2π).
 */
constexpr Real REAL_TWO_PI = 6.283185307179586476925286766559;

/**
 * @brief Complex zero literal convenience value.
 */
constexpr Complex COMPLEX_ZERO(REAL_ZERO, REAL_ZERO);

/**
 * @brief Imaginary unit constant (0 + 1i).
 */
constexpr Complex COMPLEX_IMAG_UNIT(REAL_ZERO, REAL_ONE);
} // namespace deb
