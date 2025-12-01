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

#include <cassert>
#include <cstdint>
#include <stdexcept>

/**
 * @brief Helper macro exposing the GCC version as a single integer.
 * https://gcc.gnu.org/onlinedocs/cpp/Common-Predefined-Macros.html
 */
#define GCC_VERSION                                                            \
    (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)

#if defined(__clang__)
/**
 * @brief Compiler hint requesting loop unrolling of factor 2 when supported.
 */
#define DEB_LOOP_UNROLL_2 _Pragma("clang loop unroll_count(2)")
/**
 * @brief Compiler hint requesting loop unrolling of factor 4 when supported.
 */
#define DEB_LOOP_UNROLL_4 _Pragma("clang loop unroll_count(4)")
/**
 * @brief Compiler hint requesting loop unrolling of factor 8 when supported.
 */
#define DEB_LOOP_UNROLL_8 _Pragma("clang loop unroll_count(8)")
#elif defined(__GNUG__) && GCC_VERSION > 80000 && !defined(__NVCC__)
#define DEB_LOOP_UNROLL_2 _Pragma("GCC unroll 2")
#define DEB_LOOP_UNROLL_4 _Pragma("GCC unroll 4")
#define DEB_LOOP_UNROLL_8 _Pragma("GCC unroll 8")
#else
#define DEB_LOOP_UNROLL_2
#define DEB_LOOP_UNROLL_4
#define DEB_LOOP_UNROLL_8
#endif

/**
 * @brief Converts an argument into a string literal without macro expansion.
 */
#define STR(x) #x
/**
 * @brief Converts an argument into a string literal after macro expansion.
 */
#define STRINGIFY(x) STR(x)
/**
 * @brief Invokes the PRAGMA helper with the supplied argument.
 */
#define CONCATENATE(X, Y) X(Y)
#if defined(_MSC_VER) && !defined(__INTEL_COMPILER)
#define PRAGMA(x) __pragma(x)
#else
#define PRAGMA(x) _Pragma(STRINGIFY(x))
#endif

#ifdef _MSC_VER
/**
 * @brief Decorator that hints compiler-specific pointer restrict semantics on
 * MSVC.
 */
#define DEB_RESTRICT __restrict
#else
#define DEB_RESTRICT __restrict__
#endif

#ifdef DEB_OPENMP
/**
 * @brief Emits OpenMP pragmas when DEB_OPENMP is enabled.
 */
#define PRAGMA_OMP(x) PRAGMA(x)
#else
#define PRAGMA_OMP(x)
#endif

/**
 * @brief Runtime assertion that either throws or triggers std::assert based on
 * build configuration.
 */
#ifdef DEB_RESOURCE_CHECK
#ifdef NDEBUG
#define deb_assert(condition, message)                                         \
    do {                                                                       \
        if (!(condition)) {                                                    \
            throw std::runtime_error((message));                               \
        }                                                                      \
    } while (0)
#else
#define deb_assert(condition, message)                                         \
    do {                                                                       \
        assert((condition) && (message));                                      \
    } while (0)
#endif
#else
#define deb_assert(condition, message)                                         \
    do {                                                                       \
    } while (0)
#endif
