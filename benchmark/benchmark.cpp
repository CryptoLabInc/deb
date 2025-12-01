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

#include "benchmark/benchmark.h"
#include "Decryptor.hpp"
#include "Encryptor.hpp"
#include "KeyGenerator.hpp"
#include "SecretKeyGenerator.hpp"
#include "Types.hpp"

#include <chrono>
#include <iostream>
#include <random>
#include <vector>

std::random_device rd;
std::mt19937 gen{rd()};
std::uniform_real_distribution<double> dist{-1.0, 1.0};

using namespace deb;

static Message gen_random_message(const Size num_slots) {
    Message msg(num_slots);
    for (Size i = 0; i < msg.size(); ++i) {
        msg.data()[i].real(dist(gen));
        msg.data()[i].imag(dist(gen));
    }
    return msg;
}

static CoeffMessage gen_random_coeff(const Size degree) {
    CoeffMessage coeff(degree);
    for (Size i = 0; i < degree; ++i) {
        coeff[i] = dist(gen);
    }
    return coeff;
}

template <Preset T>
static void bm_seckey_encryption(benchmark::State &state) {
    const Preset preset = T;
    const auto context = getContext(preset);
    const auto ns = context->get_num_secret();
    std::vector<Message> msg_v;
    for (Size i = 0; i < ns; ++i) {
        msg_v.push_back(gen_random_message(context->get_num_slots()));
    }

    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    Encryptor encryptor(preset);
    Ciphertext ctxt(context);

    for (auto _ : state) {
        encryptor.encrypt(msg_v, sk, ctxt);
        benchmark::DoNotOptimize(ctxt);
        benchmark::ClobberMemory();
    }
}

template <Preset T>
static void bm_enckey_encryption(benchmark::State &state) {
    const Preset preset = T;
    const auto context = getContext(preset);
    const auto ns = context->get_num_secret();
    std::vector<Message> msg_v;
    for (Size i = 0; i < ns; ++i) {
        msg_v.push_back(gen_random_message(context->get_num_slots()));
    }

    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    KeyGenerator keygen(preset);
    SwitchKey enckey = keygen.genEncKey(sk);
    Encryptor encryptor(preset);

    Ciphertext ctxt(context);
    // std::vector<Ciphertext> ctxt_v;

    for (auto _ : state) {
        encryptor.encrypt(msg_v, sk, ctxt);
        benchmark::DoNotOptimize(ctxt);
        benchmark::ClobberMemory();
        // ctxt_v.push_back(ctxt);
    }
}

template <Preset T> static void bm_decryption(benchmark::State &state) {
    const Preset preset = T;
    const auto context = getContext(preset);
    const auto ns = context->get_num_secret();
    std::vector<Message> msg_v;
    for (Size i = 0; i < ns; ++i) {
        msg_v.push_back(gen_random_message(context->get_num_slots()));
    }

    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    Encryptor encryptor(preset);
    Decryptor decryptor(preset);

    Ciphertext ctxt(context);
    encryptor.encrypt(msg_v, sk, ctxt);

    for (auto _ : state) {
        decryptor.decrypt(ctxt, sk, msg_v);
        benchmark::DoNotOptimize(msg_v.data());
        benchmark::ClobberMemory();
    }
}

template <Preset T>
static void bm_seckey_coeff_encryption(benchmark::State &state) {
    const Preset preset = T;
    const auto context = getContext(preset);
    const auto ns = context->get_num_secret();
    std::vector<CoeffMessage> msg_v;
    for (Size i = 0; i < ns; ++i) {
        msg_v.push_back(gen_random_coeff(context->get_degree()));
    }

    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    Encryptor encryptor(preset);

    Ciphertext ctxt(context);
    // std::vector<Ciphertext> ctxt_v;

    for (auto _ : state) {
        encryptor.encrypt(msg_v, sk, ctxt);
        benchmark::DoNotOptimize(ctxt);
        benchmark::ClobberMemory();
        // ctxt_v.push_back(ctxt);
    }
}

template <Preset T>
static void bm_enckey_coeff_encryption(benchmark::State &state) {
    const Preset preset = T;
    const auto context = getContext(preset);
    const auto ns = context->get_num_secret();
    std::vector<CoeffMessage> msg_v;
    for (Size i = 0; i < ns; ++i) {
        msg_v.push_back(gen_random_coeff(context->get_degree()));
    }
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    KeyGenerator keygen(preset);
    SwitchKey enckey = keygen.genEncKey(sk);
    Encryptor encryptor(preset);

    Ciphertext ctxt(context);
    // std::vector<Ciphertext> ctxt_v;

    for (auto _ : state) {
        encryptor.encrypt(msg_v, sk, ctxt);
        benchmark::DoNotOptimize(ctxt);
        benchmark::ClobberMemory();
        // ctxt_v.push_back(ctxt);
    }
}

template <Preset T>
static void bm_coeff_decryption(benchmark::State &state) {
    const Preset preset = T;
    const auto context = getContext(preset);
    const auto ns = context->get_num_secret();
    std::vector<CoeffMessage> msg_v;
    for (Size i = 0; i < ns; ++i) {
        msg_v.push_back(gen_random_coeff(context->get_degree()));
    }
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    Encryptor encryptor(preset);
    Decryptor decryptor(preset);

    Ciphertext ctxt(context);
    encryptor.encrypt(msg_v, sk, ctxt);

    for (auto _ : state) {
        decryptor.decrypt(ctxt, sk, msg_v);
        benchmark::DoNotOptimize(msg_v.data());
        benchmark::ClobberMemory();
    }
}

#define X(PRESET)                                                                   \
    BENCHMARK_TEMPLATE(bm_seckey_encryption, Preset::PRESET_##PRESET)     \
        ->Unit(benchmark::kMicrosecond);                                            \
    BENCHMARK_TEMPLATE(bm_enckey_encryption, Preset::PRESET_##PRESET)     \
        ->Unit(benchmark::kMicrosecond);                                            \
    BENCHMARK_TEMPLATE(bm_decryption, Preset::PRESET_##PRESET)            \
        ->Unit(benchmark::kMicrosecond);                                            \
    BENCHMARK_TEMPLATE(bm_seckey_coeff_encryption, Preset::PRESET_##PRESET) \
        ->Unit(benchmark::kMicrosecond);                                            \
    BENCHMARK_TEMPLATE(bm_enckey_coeff_encryption, Preset::PRESET_##PRESET) \
        ->Unit(benchmark::kMicrosecond);                                            \
    BENCHMARK_TEMPLATE(bm_coeff_decryption, Preset::PRESET_##PRESET)      \
        ->Unit(benchmark::kMicrosecond);

PRESET_LIST
#undef X
