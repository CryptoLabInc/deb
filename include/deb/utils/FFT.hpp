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
#include "CKKSTypes.hpp"

#include <complex>
#include <vector>

namespace deb::utils {

/**
 * @brief FFT implementation specialized for CKKS message containers.
 * @tparam T Floating-point type.
 */
class FFT {
public:
    /**
     * @brief Precomputes FFT twiddle factors for the requested degree.
     * @param degree Polynomial degree.
     */
    FFT(const u64 degree);

    /**
     * @brief Applies the forward FFT to a message in-place.
     * @param msg Slot-encoded message container.
     */
    template <typename T = Real> void forwardFFT(MessageImpl<T> &msg) const;
    /**
     * @brief Applies the inverse FFT to a message in-place.
     * @param msg Slot-encoded message container.
     */
    template <typename T = Real> void backwardFFT(MessageImpl<T> &msg) const;

    /**
     * @brief Returns powers of the generator used for slot rotations.
     * @param rot Rotation index.
     */
    auto getPowerOfFive(u64 rot) const { return powers_of_five_[rot]; }

private:
    // u64 degree_; // a.k.a. PolyUnit degree N
    std::vector<u64> powers_of_five_;
    std::vector<ComplexT<Real>> complex_roots_;
    std::vector<ComplexT<Real>> roots_;
    std::vector<ComplexT<Real>> inv_roots_;
};

#define DECL_FFT_TEMPLATE(T, prefix)                                           \
    prefix template void FFT::forwardFFT(MessageImpl<T> &msg) const;           \
    prefix template void FFT::backwardFFT(MessageImpl<T> &msg) const;

#define FFT_TYPE_TEMPLATE(prefix)                                              \
    DECL_FFT_TEMPLATE(Real, prefix)                                            \
    DECL_FFT_TEMPLATE(float, prefix)

FFT_TYPE_TEMPLATE(extern)

} // namespace deb::utils
