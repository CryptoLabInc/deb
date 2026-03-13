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

#include "ExampleUtils.hpp"
#include "SodiumRandomGenerator.hpp"

#include <iostream>

using namespace deb;

int main() {
    Preset preset = static_cast<Preset>(0);
    if (preset == PRESET_EMPTY) {
        std::cerr << "No preset with single secret found." << std::endl;
        return -1;
    }
    std::cout << "Preset: " << get_preset_name(preset) << std::endl;

    // -----------------------------------------------------------------
    // Test RNG
    // -----------------------------------------------------------------
    {
        RNGSeed seed = SeedGenerator::Gen();
        auto sodium_rng = std::make_shared<SodiumRandomGenerator>(seed);

        const size_t len = 16;
        std::vector<u64> rand_u64(len);
        sodium_rng->getRandomUint64Array(rand_u64.data(), len);

        std::cout << "Random u64 array:" << std::endl;
        for (size_t i = 0; i < len; ++i) {
            std::cout << "  " << rand_u64[i] << std::endl;
        }
    }
    // -----------------------------------------------------------------
    // Encrypt using SodiumRandomGenerator directly
    // -----------------------------------------------------------------
    {
        std::shared_ptr<RandomGenerator> rng = std::make_shared<SodiumRandomGenerator>(SeedGenerator::Gen());
        Encryptor enc(preset, rng);
        Decryptor dec(preset);

        SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
        Message msg = generateRandomMessage(preset);
        Message decrypted_msg(preset);
        Ciphertext ctxt(preset);

        DebTimer::start("Encrypt/Decrypt (sodium RNG direct)");
        enc.encrypt(msg, sk, ctxt);
        dec.decrypt(ctxt, sk, decrypted_msg);
        DebTimer::end();
        std::cout << "log2 error = " << compareMessage(msg, decrypted_msg)
                  << " bits" << std::endl;
    }
    // -----------------------------------------------------------------
    // Encrypt using the global factory so every RNG is Sodium-based
    // -----------------------------------------------------------------
    {
        setRandomGeneratorFactory([](const RNGSeed &seed) {
            return std::make_shared<SodiumRandomGenerator>(seed);
        });

        Encryptor enc(preset);
        KeyGenerator keygen(preset);
        Decryptor dec(preset);

        SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
        Message msg = generateRandomMessage(preset);
        Message decrypted_msg(preset);
        Ciphertext ctxt(preset);

        DebTimer::start("Encrypt/Decrypt (sodium RNG global)");
        enc.encrypt(msg, sk, ctxt);
        dec.decrypt(ctxt, sk, decrypted_msg);
        DebTimer::end();
        std::cout << "log2 error = " << compareMessage(msg, decrypted_msg)
                  << " bits" << std::endl;

        setRandomGeneratorFactory(nullptr);
    }

    std::cout << "\nDone." << std::endl;
    return 0;
}
