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
#include "Decryptor.hpp"
#include "Encryptor.hpp"
#include "KeyGenerator.hpp"
#include "Preset.hpp"
#include "SecretKeyGenerator.hpp"
#include "SeedGenerator.hpp"

#include <cmath>
#include <random>
#include <vector>

#include <gtest/gtest.h>

using namespace deb;

#if defined(DEB_RESOURCE_CHECK) && defined(NDEBUG)
#define DEB_TEST_ASSERT(statement) ASSERT_THROW(statement, std::runtime_error)
#define DEB_TEST_EXPECT(statement) EXPECT_THROW(statement, std::runtime_error)
#else
#define DEB_TEST_ASSERT(statement) ASSERT_DEATH(statement, ".*")
#define DEB_TEST_EXPECT(statement) EXPECT_DEATH(statement, ".*")
#endif

using MSGS = std::vector<Message>;
using FMSGS = std::vector<FMessage>;
using COEFFS = std::vector<CoeffMessage>;
using FCOEFFS = std::vector<FCoeffMessage>;

class DebTestBase : public ::testing::TestWithParam<Preset> {
public:
    const Preset preset{GetParam()};
    const Size num_slots{get_num_slots(preset)};
    const Size degree{get_degree(preset)};
    const Size num_secret{get_num_secret(preset)};

    Encryptor encryptor{preset};
    Decryptor decryptor{preset};
    std::random_device rd;
    std::mt19937 gen{rd()};
    std::uniform_real_distribution<double> dist{-1.0, 1.0};
    std::uniform_int_distribution<uint64_t> dist_u64{0, UINT64_MAX};
    // Adjusted error tolerances based on bitwidth of the first prime
    // 60 bit prime -> sk_err = 2^-28, enc_err = 2^-15
    // 50 bit prime -> sk_err = 2^-26.3, enc_err = 2^-13.3
    // 40 bit prime -> sk_err = 2^-24.6, enc_err = 2^-11.6
    const double log_error =
        static_cast<double>(utils::bitWidth(get_primes(preset)[0])) / 6.0;
    const double sk_err = std::pow(2.0, -18 - log_error);
    const double enc_err = std::pow(2.0, -5 - log_error);
    const double sk_err_f = std::pow(2.0, -18);
    const double enc_err_f = std::pow(2.0, -10);
    void SetUp() override {
        // Initialize any necessary resources or state before each test
    }
    void TearDown() override {
        // Clean up any resources or state after each tests
    }
    template <typename T> T scale_message(T &msg, uint32_t level) {
        const double scale = get_scale_factors(preset)[level];
        if (scale == 0.0) {
            const double scale =
                std::pow(2.0, utils::bitWidth(get_primes(preset)[0]) - 4);
            T scale_msg = gen_empty_message<T>();
            for (Size i = 0; i < num_secret; ++i) {
                for (Size j = 0; j < num_slots; ++j) {
                    scale_msg[i][j].real(msg[i][j].real() * scale);
                    scale_msg[i][j].imag(msg[i][j].imag() * scale);
                }
            }
            return scale_msg;
        }
        return msg;
    }
    COEFFS scale_coeff(COEFFS &coeffs, uint32_t level) {
        const double scale = get_scale_factors(preset)[level];
        if (scale == 0.0) {
            const double scale =
                std::pow(2.0, utils::bitWidth(get_primes(preset)[0]) - 4);
            COEFFS scale_coeffs = gen_empty_coeff<COEFFS>();
            for (Size i = 0; i < num_secret; ++i) {
                for (Size j = 0; j < degree; ++j) {
                    scale_coeffs[i][j] = coeffs[i][j] * scale;
                }
            }
            return scale_coeffs;
        }
        return coeffs;
    }
    double scale_error(double err, uint32_t level) {
        const double scale = get_scale_factors(preset)[level];
        if (scale == 0.0) {
            const double scale =
                std::pow(2.0, utils::bitWidth(get_primes(preset)[0]) - 4);
            return err * scale;
        }
        return err;
    }
    template <typename T> T gen_empty_message() {
        T msg;
        for (Size i = 0; i < num_secret; ++i) {
            msg.emplace_back(num_slots);
        }
        return msg;
    }
    template <typename T> T gen_random_message() {
        T msg;
        for (Size i = 0; i < num_secret; ++i) {
            if constexpr (std::is_same_v<T, FMSGS>) {
                FMessage m(num_slots);
                for (Size j = 0; j < num_slots; ++j) {
                    m[j].real(static_cast<float>(dist(gen)));
                    m[j].imag(static_cast<float>(dist(gen)));
                }
                msg.emplace_back(std::move(m));
            } else if constexpr (std::is_same_v<T, MSGS>) {
                Message m(num_slots);
                for (Size j = 0; j < num_slots; ++j) {
                    m[j].real(dist(gen));
                    m[j].imag(dist(gen));
                }
                msg.emplace_back(std::move(m));
            }
        }
        return msg;
    }
    template <typename T> T gen_empty_coeff() {
        T coeffs;
        for (Size i = 0; i < num_secret; ++i) {
            coeffs.emplace_back(degree);
        }
        return coeffs;
    }
    template <typename T> T gen_random_coeff() {
        T coeffs;
        for (Size i = 0; i < num_secret; ++i) {
            if constexpr (std::is_same_v<T, FCOEFFS>) {
                FCoeffMessage coeff(degree);
                for (Size j = 0; j < coeff.size(); ++j) {
                    coeff[j] = static_cast<float>(dist(gen));
                }
                coeffs.emplace_back(std::move(coeff));
            } else if constexpr (std::is_same_v<T, COEFFS>) {
                CoeffMessage coeff(degree);
                for (Size j = 0; j < coeff.size(); ++j) {
                    coeff[j] = dist(gen);
                }
                coeffs.emplace_back(std::move(coeff));
            }
        }
        return coeffs;
    }
    template <typename T> void compare_msg(T &msg1, T &msg2, double tol) const {
        for (Size i = 0; i < num_secret; ++i) {
            for (Size j = 0; j < num_slots; ++j) {
                ASSERT_NEAR(msg1[i][j].real(), msg2[i][j].real(), tol);
                ASSERT_NEAR(msg1[i][j].imag(), msg2[i][j].imag(), tol);
            }
        }
    }
    template <typename T>
    void compare_coeff(T &coeff1, T &coeff2, double tol) const {
        for (Size i = 0; i < num_secret; ++i) {
            for (Size j = 0; j < degree; ++j) {
                ASSERT_NEAR(coeff1[i][j], coeff2[i][j], tol);
            }
        }
    }
    template <typename T>
    void compareArray(const T *arr1, const T *arr2, const Size size) {
        for (Size i = 0; i < size; ++i) {
            ASSERT_EQ(arr1[i], arr2[i]);
        }
    }

    void comparePolyUnit(const PolyUnit &poly1, const PolyUnit &poly2) {
        ASSERT_EQ(poly1.prime(), poly2.prime());
        ASSERT_EQ(poly1.degree(), poly2.degree());
        ASSERT_EQ(poly1.isNTT(), poly2.isNTT());
        compareArray(poly1.data(), poly2.data(), poly1.degree());
    }

    void comparePoly(const Polynomial &bigpoly1, const Polynomial &bigpoly2) {
        ASSERT_EQ(bigpoly1.size(), bigpoly2.size());
        for (Size i = 0; i < bigpoly1.size(); ++i) {
            comparePolyUnit(bigpoly1[i], bigpoly2[i]);
        }
    }
};
