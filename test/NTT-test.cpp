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

#include "utils/Basic.hpp"
#include "utils/NTT.hpp"

#include <vector>

#include <gtest/gtest.h>

using namespace deb;
using namespace std;

namespace {
void getRandomU64RangeIter(Size range, u64 *begin, const u64 *end) {
    for (u64 *it = begin; it != end; ++it) {
        *it = static_cast<u64>(rand()) % range;
    }
}
} // namespace

class NttTest : public ::testing::TestWithParam<std::tuple<u64, u64>> {
public:
    const u64 degree{get<0>(GetParam())};
    const u64 prime{get<1>(GetParam())};

    auto getRandomVector(Size size = 0) const {
        if (size == 0)
            size = degree;
        // std::vector<u64> v(size);
        auto *v = static_cast<u64 *>(
            ::operator new[](sizeof(u64) * size, std::align_val_t(256)));
        getRandomU64RangeIter(prime, v, v + size);
        return v;
    }
};

inline u64 findMinPrimitiveRoot(u64 degree, u64 prime) {
    auto mult_with_barr = [](u64 x, u64 y, u64 y_barr, u64 prime) {
        u64 res = utils::mulModLazy(x, y, y_barr, prime);
        return utils::subIfGE(res, prime);
    };

    u64 psi = utils::findPrimitiveRoot(prime);
    // Nth root of unity
    psi = utils::powModSimple(psi, (prime - 1) / (degree), prime);

    // Find the minimal 2N-th root of unity
    u64 psi_square = utils::mulModSimple(psi, psi, prime);
    u64 psi_square_barr = utils::divide128By64Lo(psi_square, 0, prime);
    u64 min_root = psi;
    u64 psi_tmp = psi;
    for (u64 i = 0; i < degree; ++i) {
        psi_tmp = mult_with_barr(psi_tmp, psi_square, psi_square_barr, prime);
        if (psi_tmp < min_root)
            min_root = psi_tmp;
    }
    psi = min_root;
    return psi;
}

TEST_P(NttTest, SameAfterNTTandiNTT) {
    utils::NTT ntt{degree, prime};

    auto *op = getRandomVector();
    auto *res = op;

    ntt.computeForward(res);
    ntt.computeBackward(res);

    EXPECT_EQ(res, op);
}

TEST_P(NttTest, PerformNTTforOneZeroVector) {
    utils::NTT ntt{degree, prime};

    std::vector<u64> op1(degree);
    op1[0] = 1;
    std::vector<u64> op2(degree, 1);

    ntt.computeForward(op1.data());

    EXPECT_EQ(op1, op2);
}

INSTANTIATE_TEST_SUITE_P(61bitPrimes, NttTest,
                         testing::Values(std::tuple{1 << 15,
                                                    2305843009146585089}));
INSTANTIATE_TEST_SUITE_P(40bitPrimes, NttTest,
                         testing::Values(std::tuple{1 << 13, 2199020634113}));

INSTANTIATE_TEST_SUITE_P(TinyDegree, NttTest,
                         testing::Values(std::tuple{64, 4295688193}));
