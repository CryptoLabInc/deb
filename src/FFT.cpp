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

#include "utils/FFT.hpp"
#include "utils/Basic.hpp"
#include "utils/Constant.hpp"
#include "utils/Macro.hpp"

#include <complex>
namespace {

template <typename T> void bitReverseMessage(deb::MessageImpl<T> &m) {
    deb::utils::bitReverseArray(m.data(), m.size());
}

// Direction = true : forward FFT
// Direction = false : backward FFT
template <bool Direction, typename T>
inline void butterfly(deb::ComplexT<T> &u, deb::ComplexT<T> &v,
                      const deb::ComplexT<double> root) {
    if constexpr (Direction) {
        deb::ComplexT<double> u0 = u;
        deb::ComplexT<double> v0 = static_cast<deb::ComplexT<double>>(v) * root;
        u = static_cast<deb::ComplexT<T>>(u0 + v0);
        v = static_cast<deb::ComplexT<T>>(u0 - v0);
    } else {
        deb::ComplexT<T> u0 = u;
        deb::ComplexT<T> v0 = v;
        u = u0 + v0;
        v = (u0 - v0) * static_cast<deb::ComplexT<T>>(root);
    }
}

template <bool Direction, typename T>
void computeSingleStep(deb::ComplexT<T> *op, deb::Size size, deb::Size gap,
                       const deb::ComplexT<double> *roots_ptr) {
    if (gap > 4 || size < 8) {
        deb::ComplexT<T> *x_ptr = op;
        deb::ComplexT<T> *y_ptr = op + gap;
        for (deb::Size i = size / 2 / gap; i != 0; --i) {
            DEB_LOOP_UNROLL_4
            for (deb::Size j = 0; j < gap; ++j) {
                butterfly<Direction, T>(*x_ptr++, *y_ptr++, roots_ptr[j]);
            }
            x_ptr += gap;
            y_ptr += gap;
        }

        return;
    }

    // optimization for small gap
    static std::array<deb::ComplexT<T>, 4> root;
    if (gap <= 4)
        for (deb::u64 i = 0; i < gap; ++i)
            root[i] = roots_ptr[i];

    switch (gap) {
    case 1:
        DEB_LOOP_UNROLL_4
        for (deb::Size i = size >> 3; i != 0; --i, op += 8) {
            butterfly<Direction, T>(op[0], op[1], root[0]);
            butterfly<Direction, T>(op[2], op[3], root[0]);
            butterfly<Direction, T>(op[4], op[5], root[0]);
            butterfly<Direction, T>(op[6], op[7], root[0]);
        }
        break;
    case 2:
        DEB_LOOP_UNROLL_4
        for (deb::Size i = size >> 3; i != 0; --i, op += 8) {
            butterfly<Direction, T>(op[0], op[2], root[0]);
            butterfly<Direction, T>(op[1], op[3], root[1]);
            butterfly<Direction, T>(op[4], op[6], root[0]);
            butterfly<Direction, T>(op[5], op[7], root[1]);
        }
        break;
    case 4:
        DEB_LOOP_UNROLL_4
        for (deb::Size i = size >> 3; i != 0; --i, op += 8) {
            butterfly<Direction, T>(op[0], op[4], root[0]);
            butterfly<Direction, T>(op[1], op[5], root[1]);
            butterfly<Direction, T>(op[2], op[6], root[2]);
            butterfly<Direction, T>(op[3], op[7], root[3]);
        }
        break;
    default:
        break;
    }
}

} // namespace

namespace deb::utils {

template <typename T> void FFT::forwardFFT(MessageImpl<T> &msg) const {
    const Size sz{msg.size()};
    const auto *roots_ptr = roots_.data();
    bitReverseMessage(msg);
    for (Size gap = 1; gap <= sz / 2; gap <<= 1) {
        computeSingleStep<true, T>(msg.data(), sz, gap, roots_ptr + gap);
    }
}

template <typename T> void FFT::backwardFFT(MessageImpl<T> &msg) const {
    const Size sz{msg.size()};
    const auto *roots_ptr = inv_roots_.data();
    for (Size gap = sz / 2; gap != 0; gap >>= 1)
        computeSingleStep<false, T>(msg.data(), sz, gap, roots_ptr + gap);
    bitReverseMessage(msg);
    for (Size i = 0; i < sz; ++i)
        msg[i] = {msg[i].real() / static_cast<T>(sz),
                  msg[i].imag() / static_cast<T>(sz)};
}

FFT::FFT(const u64 degree) {
    // pre-compute the power of five
    const u64 half_degree = degree >> 1;
    const u64 double_degree = degree << 1;
    const u64 double_degree_mask = double_degree - 1;
    powers_of_five_.resize(half_degree);
    for (u64 i = 0, pow = 1; i < half_degree; ++i) {
        powers_of_five_[i] = pow;
        pow = (pow * 5) & double_degree_mask; // (pow * 5) % double_degree
    }
    complex_roots_.resize(double_degree + 1);
    for (u64 i = 0; i < double_degree; ++i) {
        Real angle = REAL_PI * static_cast<Real>(i) / static_cast<Real>(degree);
        const ComplexT<Real> w{0.0, 1.0};
        const auto tmp = std::exp(w * angle);
        complex_roots_[i] = {tmp.real(), tmp.imag()};
    }
    complex_roots_[double_degree] = complex_roots_[0];

    roots_.resize(half_degree);
    inv_roots_.resize(half_degree);
    for (u64 gap = half_degree / 2; gap != 0; gap >>= 1) {
        u64 len = half_degree / 2 / gap;
        for (u64 i = 0; i < len; ++i) {
            u64 idx = (powers_of_five_[i] * gap) & (double_degree - 1);
            roots_[len + i] = complex_roots_[idx];
            inv_roots_[len + i] = complex_roots_[double_degree - idx];
        }
    }
}

FFT_TYPE_TEMPLATE()

} // namespace deb::utils
