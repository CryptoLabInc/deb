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

#include "utils/RandomGenerator.hpp"
#include "utils/AleaRandomGenerator.hpp"

#include <mutex>

namespace deb {

namespace {
std::mutex g_factory_mutex;
RandomGeneratorFactory g_factory;
} // namespace

// Sets a custom random generator factory.
// The factory should be a function that takes an RNGSeed and
// returns a shared pointer to a RandomGenerator.
// The custom generator must ensure that the unpredictability,
// unbiased, forward/backward security properties hold for the
// generated random values. To reset to the default random
// generator, call setRandomGeneratorFactory with an empty factory or nullptr.
void setRandomGeneratorFactory(RandomGeneratorFactory factory) {
    std::lock_guard<std::mutex> lock(g_factory_mutex);
    g_factory = std::move(factory);
}

std::shared_ptr<RandomGenerator> createRandomGenerator(const RNGSeed &seed) {
    RandomGeneratorFactory factory_copy;
    {
        std::lock_guard<std::mutex> lock(g_factory_mutex);
        factory_copy = g_factory;
    }
    if (factory_copy) {
        return factory_copy(seed);
    }
    return std::make_shared<AleaRandomGenerator>(seed);
}

} // namespace deb
