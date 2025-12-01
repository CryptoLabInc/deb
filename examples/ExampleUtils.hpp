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
#include "Serialize.hpp"

#include <chrono>
#include <iostream>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

extern std::vector<deb::Preset> Presets;

class DebTimer {
    std::string name_;
    std::chrono::high_resolution_clock::time_point start_;
    std::optional<double> elapsed_;
    static DebTimer *instance_;
    static std::mutex mtx_;
    DebTimer();

    void start_impl(const char *name);
    void end_impl();

public:
    // Singleton instance retrieval
    static DebTimer &get();
    static void start(const char *name);
    static void end();

    // Destructor for automatic end (rarely called due to singleton nature)
    ~DebTimer();
};

deb::Message generateRandomMessage(const deb::Preset preset);
deb::CoeffMessage generateRandomCoeffMessage(const deb::Preset preset);

double compareMessages(const std::vector<deb::Message> &msgs1,
                       const std::vector<deb::Message> &msgs2);
double compareMessage(const deb::Message &msg1,
                      const deb::Message &msg2);

double compareCoeffs(const std::vector<deb::CoeffMessage> &coeffs1,
                     const std::vector<deb::CoeffMessage> &coeffs2);
double compareCoeff(const deb::CoeffMessage &coeff1,
                    const deb::CoeffMessage &coeff2);
