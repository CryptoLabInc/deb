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

#include <cstring>
#include <random>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

using namespace deb;

template <typename T> class FFTTest : public ::testing::Test {};
using FFTTypes = ::testing::Types<Real, float>;
TYPED_TEST_SUITE(FFTTest, FFTTypes);

// Two threads share one FFT object. Thread 0 runs forward-then-backward and
// thread 1 backward-then-forward, so they use different twiddle factors at the
// same time. Each result must match the same sequence run on one thread, bit
// for bit.
TYPED_TEST(FFTTest, ConcurrentMatchesSingleThread) {
    using T = TypeParam;
    constexpr u64 kDegree = 1 << 12;
    constexpr Size kSlots = kDegree / 2;
    constexpr int kRounds = 200;

    const utils::FFT fft(kDegree);

    auto run = [&](MessageImpl<T> &msg, bool forward_first) {
        for (int r = 0; r < kRounds; ++r) {
            if (forward_first) {
                fft.forwardFFT(msg);
                fft.backwardFFT(msg);
            } else {
                fft.backwardFFT(msg);
                fft.forwardFFT(msg);
            }
        }
    };

    std::mt19937 gen{42};
    std::uniform_real_distribution<T> dist{-1, 1};
    std::vector<MessageImpl<T>> inputs;
    for (int t = 0; t < 2; ++t) {
        inputs.emplace_back(kSlots);
        for (Size i = 0; i < kSlots; ++i)
            inputs[t][i] = ComplexT<T>(dist(gen), dist(gen));
    }

    std::vector<MessageImpl<T>> expected = inputs;
    run(expected[0], true);
    run(expected[1], false);

    std::vector<MessageImpl<T>> actual = inputs;
    std::thread t0([&] { run(actual[0], true); });
    std::thread t1([&] { run(actual[1], false); });
    t0.join();
    t1.join();

    for (int t = 0; t < 2; ++t) {
        EXPECT_EQ(0, std::memcmp(expected[t].data(), actual[t].data(),
                                 kSlots * sizeof(ComplexT<T>)))
            << "thread " << t << " result differs from the single-thread run";
    }
}
