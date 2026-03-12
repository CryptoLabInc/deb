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

#if !defined(__STDC_WANT_LIB_EXT1__)
#define __STDC_WANT_LIB_EXT1__ 1
#endif

#include <cassert>
#include <cstdint>
#include <cstring> // explicit_bzero / memset
#include <stdexcept>

#if defined(DEB_SECURE_ZERO_LIBSODIUM)
#include <sodium.h>
#elif defined(DEB_SECURE_ZERO_OPENSSL)
#include <openssl/crypto.h>
#elif defined(DEB_SECURE_ZERO_NATIVE)
#if defined(_WIN32) || defined(_WIN64)
#define NOMINMAX
#include <windows.h>
#endif
#endif

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

/* Compile-time detection of secure memory-zeroing primitive.
 * Priority:
 *  1. explicit_bzero  – glibc >= 2.25, OpenBSD, FreeBSD >= 11, NetBSD, macOS
 *  2. SecureZeroMemory – Windows
 *  3. memset_s        – C11 Annex K (implementation defines __STDC_LIB_EXT1__)
 *  4. volatile loop   – fallback
 *
 * On glibc without _GNU_SOURCE, string.h does not declare explicit_bzero even
 * though the symbol exists in libc; supply a forward declaration in that case.
 */
#if defined(__GLIBC__) &&                                                      \
    (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25))
#define DEB_HAVE_EXPLICIT_BZERO
#ifndef _GNU_SOURCE
extern void explicit_bzero(void *, size_t);
#endif
#elif defined(__OpenBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 11) ||   \
    defined(__NetBSD__) || defined(__APPLE__)
#define DEB_HAVE_EXPLICIT_BZERO
#elif defined(_WIN32) || defined(_WIN64)
#define DEB_HAVE_SECURE_ZERO_MEMORY
#elif defined(__STDC_LIB_EXT1__)
#define DEB_HAVE_MEMSET_S
#endif

/**
 * @brief Securely zeroes memory to prevent sensitive data leakage.
 * @param ptr Pointer to the memory region.
 * @param len Length of the memory region in bytes.
 */
inline void deb_secure_zero(void *ptr, std::size_t len) noexcept {
    if (ptr == nullptr || len == 0)
        return;
#if defined(DEB_SECURE_ZERO_LIBSODIUM)
    sodium_memzero(ptr, len);
#elif defined(DEB_SECURE_ZERO_OPENSSL)
    OPENSSL_cleanse(ptr, len);
#elif defined(DEB_SECURE_ZERO_NATIVE)
#if defined(DEB_HAVE_SECURE_ZERO_MEMORY)
    SecureZeroMemory(ptr, len);
#elif defined(DEB_HAVE_EXPLICIT_BZERO)
    explicit_bzero(ptr, len);
#elif defined(DEB_HAVE_MEMSET_S)
    memset_s(ptr, len, 0, len);
#else
    // volatile byte loop — best-effort against compiler optimisation
    volatile unsigned char *p = static_cast<volatile unsigned char *>(ptr);
    for (std::size_t i = 0; i < len; ++i)
        p[i] = 0;
#endif
#else // DEB_SECURE_ZERO is not seted (NONE)
    // Fallback to memset, does not guarantee zeroing against compiler
    // optimizations, but better than nothing
    std::memset(ptr, 0, len);
#endif
}
