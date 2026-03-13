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
std::uniform_int_distribution<deb::u64> dist_u64;

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
    const auto ns = get_num_secret(preset);
    std::vector<Message> msg_v;
    for (Size i = 0; i < ns; ++i) {
        msg_v.push_back(gen_random_message(get_num_slots(preset)));
    }

    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    EncryptorT<T> encryptor;
    Ciphertext ctxt(preset);

    for (auto _ : state) {
        encryptor.encrypt(msg_v, sk, ctxt);
        benchmark::DoNotOptimize(ctxt);
        benchmark::ClobberMemory();
    }
}

template <Preset T>
static void bm_enckey_encryption(benchmark::State &state) {
    const Preset preset = T;
    const auto ns = get_num_secret(preset);
    std::vector<Message> msg_v;
    for (Size i = 0; i < ns; ++i) {
        msg_v.push_back(gen_random_message(get_num_slots(preset)));
    }

    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    KeyGenerator keygen(preset);
    SwitchKey enckey = keygen.genEncKey(sk);
    EncryptorT<T> encryptor;
    Ciphertext ctxt(preset);

    for (auto _ : state) {
        encryptor.encrypt(msg_v, enckey, ctxt);
        benchmark::DoNotOptimize(ctxt);
        benchmark::ClobberMemory();
    }
}

template <Preset T> static void bm_decryption(benchmark::State &state) {
    const Preset preset = T;
    const auto ns = get_num_secret(preset);
    std::vector<Message> msg_v;
    for (Size i = 0; i < ns; ++i) {
        msg_v.push_back(gen_random_message(get_num_slots(preset)));
    }

    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    EncryptorT<T> encryptor;
    DecryptorT<T> decryptor;
    Ciphertext ctxt(preset);
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
    const auto ns = get_num_secret(preset);
    std::vector<CoeffMessage> msg_v;
    for (Size i = 0; i < ns; ++i) {
        msg_v.push_back(gen_random_coeff(get_degree(preset)));
    }

    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    EncryptorT<T> encryptor;
    Ciphertext ctxt(preset);

    for (auto _ : state) {
        encryptor.encrypt(msg_v, sk, ctxt);
        benchmark::DoNotOptimize(ctxt);
        benchmark::ClobberMemory();
    }
}

template <Preset T>
static void bm_enckey_coeff_encryption(benchmark::State &state) {
    const Preset preset = T;
    const auto ns = get_num_secret(preset);
    std::vector<CoeffMessage> msg_v;
    for (Size i = 0; i < ns; ++i) {
        msg_v.push_back(gen_random_coeff(get_degree(preset)));
    }
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    KeyGenerator keygen(preset);
    SwitchKey enckey = keygen.genEncKey(sk);
    EncryptorT<T> encryptor;
    Ciphertext ctxt(preset);

    for (auto _ : state) {
        encryptor.encrypt(msg_v, enckey, ctxt);
        benchmark::DoNotOptimize(ctxt);
        benchmark::ClobberMemory();
    }
}

template <Preset T>
static void bm_coeff_decryption(benchmark::State &state) {
    const Preset preset = T;
    const auto ns = get_num_secret(preset);
    std::vector<CoeffMessage> msg_v;
    for (Size i = 0; i < ns; ++i) {
        msg_v.push_back(gen_random_coeff(get_degree(preset)));
    }
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    EncryptorT<T> encryptor(preset);
    DecryptorT<T> decryptor(preset);

    Ciphertext ctxt(preset);
    encryptor.encrypt(msg_v, sk, ctxt);

    for (auto _ : state) {
        decryptor.decrypt(ctxt, sk, msg_v);
        benchmark::DoNotOptimize(msg_v.data());
        benchmark::ClobberMemory();
    }
}

template <Size degree, u64 prime>
static void bm_forward_ntt(benchmark::State &state) {
    utils::NTT ntt(degree, prime);
    u64 data[degree];

    for (auto _ : state) {
        state.PauseTiming();
        for (Size i = 0; i < degree; ++i) {
            data[i] = dist_u64(gen) % prime;
        }
        state.ResumeTiming();
        ntt.computeForward(data);
        benchmark::DoNotOptimize(data);
        benchmark::ClobberMemory();
    }
}

template <Size degree, u64 prime>
static void bm_backward_ntt(benchmark::State &state) {
    utils::NTT ntt(degree, prime);
    u64 data[degree];

    for (auto _ : state) {
        state.PauseTiming();
        for (Size i = 0; i < degree; ++i) {
            data[i] = dist_u64(gen) % prime;
        }
        ntt.computeForward(data);
        state.ResumeTiming();
        ntt.computeBackward(data);
        benchmark::DoNotOptimize(data);
        benchmark::ClobberMemory();
    }
}

#define X(PRESET)                                                           \
    BENCHMARK_TEMPLATE(bm_seckey_encryption, Preset::PRESET_##PRESET)       \
        ->Unit(benchmark::kMicrosecond);                                    \
    BENCHMARK_TEMPLATE(bm_enckey_encryption, Preset::PRESET_##PRESET)       \
        ->Unit(benchmark::kMicrosecond);                                    \
    BENCHMARK_TEMPLATE(bm_decryption, Preset::PRESET_##PRESET)              \
        ->Unit(benchmark::kMicrosecond);                                    \
    BENCHMARK_TEMPLATE(bm_seckey_coeff_encryption, Preset::PRESET_##PRESET) \
        ->Unit(benchmark::kMicrosecond);                                    \
    BENCHMARK_TEMPLATE(bm_enckey_coeff_encryption, Preset::PRESET_##PRESET) \
        ->Unit(benchmark::kMicrosecond);                                    \
    BENCHMARK_TEMPLATE(bm_coeff_decryption, Preset::PRESET_##PRESET)        \
        ->Unit(benchmark::kMicrosecond);

PRESET_LIST
#undef X

BENCHMARK_TEMPLATE(bm_forward_ntt, 65536, 288230376147386369)->Unit(benchmark::kMicrosecond);
BENCHMARK_TEMPLATE(bm_backward_ntt, 65536, 288230376147386369)
    ->Unit(benchmark::kMicrosecond);
