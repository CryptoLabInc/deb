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
#include "Context.hpp"
#include "Decryptor.hpp"
#include "Encryptor.hpp"
#include "KeyGenerator.hpp"
#include "SecretKeyGenerator.hpp"
#include "SeedGenerator.hpp"

#include <cmath>
#include <random>
#include <vector>

#include <gtest/gtest.h>

using namespace deb;

#if defined(DEB_RESOURCE_CHECK) && defined(NDEBUG)
#define DEB_ASSERT(statement) ASSERT_THROW(statement, std::runtime_error)
#define DEB_EXPECT(statement) EXPECT_THROW(statement, std::runtime_error)
#else
#define DEB_ASSERT(statement) ASSERT_DEATH(statement, ".*")
#define DEB_EXPECT(statement) EXPECT_DEATH(statement, ".*")
#endif

using MSGS = std::vector<Message>;
using COEFFS = std::vector<CoeffMessage>;

class DebTestBase : public ::testing::TestWithParam<Preset> {
public:
    const Preset preset{GetParam()};
    Context context{getContext(preset)};
    const Size num_slots{context->get_num_slots()};
    const Size degree{context->get_degree()};
    const Size num_secret{context->get_num_secret()};

    Encryptor encryptor{preset};
    Decryptor decryptor{preset};
    std::random_device rd;
    std::mt19937 gen{rd()};
    std::uniform_real_distribution<double> dist{-1.0, 1.0};
    // Adjusted error tolerances based on bitwidth of the first prime
    // 60 bit prime -> sk_err = 2^-28, enc_err = 2^-15
    // 50 bit prime -> sk_err = 2^-26.3, enc_err = 2^-13.3
    // 40 bit prime -> sk_err = 2^-24.6, enc_err = 2^-11.6
    const double log_error =
        static_cast<double>(utils::bitWidth(context->get_primes()[0])) / 6.0;
    const double sk_err = std::pow(2.0, -18 - log_error);
    const double enc_err = std::pow(2.0, -5 - log_error);
    void SetUp() override {
        // Initialize any necessary resources or state before each test
    }
    void TearDown() override {
        // Clean up any resources or state after each tests
    }
    MSGS scale_message(MSGS &msg, uint32_t level) {
        const double scale = context->get_scale_factors()[level];
        if (scale == 0.0) {
            const double scale =
                std::pow(2.0, utils::bitWidth(context->get_primes()[0]) - 4);
            MSGS scale_msg = gen_empty_message();
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
        const double scale = context->get_scale_factors()[level];
        if (scale == 0.0) {
            const double scale =
                std::pow(2.0, utils::bitWidth(context->get_primes()[0]) - 4);
            COEFFS scale_coeffs = gen_empty_coeff();
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
        const double scale = context->get_scale_factors()[level];
        if (scale == 0.0) {
            const double scale =
                std::pow(2.0, utils::bitWidth(context->get_primes()[0]) - 4);
            return err * scale;
        }
        return err;
    }
    MSGS gen_empty_message() {
        MSGS msg;
        for (Size i = 0; i < num_secret; ++i) {
            msg.emplace_back(num_slots);
        }
        return msg;
    }
    MSGS gen_random_message() {
        MSGS msg;
        for (Size i = 0; i < num_secret; ++i) {
            Message m(num_slots);
            for (Size j = 0; j < num_slots; ++j) {
                m[j].real(dist(gen));
                m[j].imag(dist(gen));
            }
            msg.emplace_back(std::move(m));
        }
        return msg;
    }
    COEFFS gen_empty_coeff() {
        COEFFS coeffs;
        for (Size i = 0; i < num_secret; ++i) {
            coeffs.emplace_back(degree);
        }
        return coeffs;
    }
    COEFFS gen_random_coeff() {
        COEFFS coeffs;
        for (Size i = 0; i < num_secret; ++i) {
            CoeffMessage coeff(degree);
            for (Size j = 0; j < coeff.size(); ++j) {
                coeff[j] = dist(gen);
            }
            coeffs.emplace_back(std::move(coeff));
        }
        return coeffs;
    }

    void compare_msg(MSGS &msg1, MSGS &msg2, double tol) const {
        for (Size i = 0; i < num_secret; ++i) {
            for (Size j = 0; j < num_slots; ++j) {
                ASSERT_NEAR(msg1[i][j].real(), msg2[i][j].real(), tol);
                ASSERT_NEAR(msg1[i][j].imag(), msg2[i][j].imag(), tol);
            }
        }
    }
    void compare_coeff(COEFFS &coeff1, COEFFS &coeff2, double tol) const {
        for (Size i = 0; i < num_secret; ++i) {
            for (Size j = 0; j < degree; ++j) {
                ASSERT_NEAR(coeff1[i][j], coeff2[i][j], tol);
            }
        }
    }
};
