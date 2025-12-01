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

#include "ExampleUtils.hpp"

#include <limits>
#include <random>


#define X(preset) deb::PRESET_##preset,
std::vector<deb::Preset> Presets = {
    PRESET_LIST
};
#undef X

DebTimer::DebTimer() : elapsed_(std::nullopt) {}

DebTimer &DebTimer::get() {
    static DebTimer instance;
    return instance;
}

void DebTimer::start(const char *name) { get().start_impl(name); }

void DebTimer::end() { get().end_impl(); }

void DebTimer::start_impl(const char *name) {
    end_impl(); // End previous timing if any
    name_ = name;
    start_ = std::chrono::high_resolution_clock::now();
    elapsed_ = std::nullopt;
}

void DebTimer::end_impl() {
    if (!elapsed_ && !name_.empty()) {
        auto end = std::chrono::high_resolution_clock::now();
        double ms =
            std::chrono::duration<double, std::milli>(end - start_).count();
        std::cout << "[TIMER] " << name_ << ": " << ms << " ms" << std::endl;
        elapsed_ = ms;
    }
}

DebTimer::~DebTimer() { end(); }

// Initialize static members
DebTimer *DebTimer::instance_ = nullptr;
std::mutex DebTimer::mtx_;

std::random_device rd;  // Obtain a random number from hardware
// Define a uniform distribution
std::uniform_real_distribution<deb::Real> dist(-1.0, 1.0);

deb::Message generateRandomMessage(const deb::Preset preset) {
    static std::mt19937 eng(rd()); // Seed the generator
    deb::Message msg(preset);
    for (size_t i = 0; i < msg.size(); ++i) {
        msg[i].real(dist(eng));
        msg[i].imag(dist(eng));
    }
    return msg;
}

deb::CoeffMessage generateRandomCoeffMessage(const deb::Preset preset) {
    static std::mt19937 eng(rd()); // Seed the generator
    deb::CoeffMessage cmsg(preset);
    for (size_t i = 0; i < cmsg.size(); ++i) {
        cmsg[i] = dist(eng);
    }
    return cmsg;
}

double compareMessages(const std::vector<deb::Message> &msgs1,
                       const std::vector<deb::Message> &msgs2) {
    if (msgs1.size() != msgs2.size()) {
        throw std::invalid_argument(
            "[compareMessages] Message vector size mismatch");
    }
    double max_diff = -std::numeric_limits<double>::infinity();
    for (size_t i = 0; i < msgs1.size(); ++i) {
        max_diff = std::max(max_diff, compareMessage(msgs1[i], msgs2[i]));
    }
    return max_diff;

}
double compareMessage(const deb::Message &msg1,
                      const deb::Message &msg2) {
    if (msg1.size() != msg2.size()) {
        throw std::invalid_argument(
            "[compareMessage] Message size mismatch");
    }
    double max_diff = 0.0;
    for (size_t i = 0; i < msg1.size(); ++i) {
        double diff_real = msg1[i].real() - msg2[i].real();
        double diff_imag = msg1[i].imag() - msg2[i].imag();
        double abs_diff = std::sqrt(diff_real * diff_real +
                                    diff_imag * diff_imag);
        max_diff = std::max(max_diff, abs_diff);
    }
    return std::log2(max_diff);
}

double compareCoeffs(const std::vector<deb::CoeffMessage> &coeffs1,
                     const std::vector<deb::CoeffMessage> &coeffs2) {
    if (coeffs1.size() != coeffs2.size()) {
        throw std::invalid_argument(
            "[compareCoeffs] Coefficient vector size mismatch");
    }
    double max_diff = -std::numeric_limits<double>::infinity();
    for (size_t i = 0; i < coeffs1.size(); ++i) {
        max_diff = std::max(max_diff, compareCoeff(coeffs1[i], coeffs2[i]));
    }
    return max_diff;
}

double compareCoeff(const deb::CoeffMessage &coeff1,
                    const deb::CoeffMessage &coeff2) {
    if (coeff1.size() != coeff2.size()) {
        throw std::invalid_argument(
            "[compareCoeff] Coefficient size mismatch");
    }
    double max_diff = 0.0;
    for (size_t i = 0; i < coeff1.size(); ++i) {
        double diff = std::abs(coeff1[i] - coeff2[i]);
        max_diff = std::max(max_diff, diff);
    }
    return std::log2(max_diff);
}
