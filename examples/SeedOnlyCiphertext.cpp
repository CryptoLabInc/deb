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

// Demonstrates seed-only 'a' ciphertexts:
//   * The 'a' part (the last-index polynomial) is released after encryption and
//     only the RNG seed is kept, reducing storage. It is regenerated on demand.
//   * The Gaussian-error seed can be supplied for deterministic encryption.

#include "ExampleUtils.hpp"
#ifdef DEB_SERIALIZE
#include "Serialize.hpp"
#endif

using namespace deb;

int main() {
    // Pick a single-secret preset.
    Preset preset = PRESET_EMPTY;
    for (auto p : Presets) {
        if (get_num_secret(p) == 1) {
            preset = p;
            break;
        }
    }
    if (preset == PRESET_EMPTY) {
        std::cerr << "No preset with single secret found." << std::endl;
        return -1;
    }
    std::cout << "Preset: " << get_preset_name(preset) << std::endl;

    Encryptor enc(preset);
    Decryptor dec(preset);
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    Message msg = generateRandomMessage(preset);

    // ---------------------------------------------------------------------
    // 1. Secret-key seed-only encryption
    // ---------------------------------------------------------------------
    {
        Ciphertext full(preset);
        enc.encrypt(msg, sk, full); // ordinary ciphertext

        Ciphertext seed_only(preset);
        enc.encrypt(msg, sk, seed_only, EncryptOptions().SeedOnlyA(true));
        std::cout << "\n[Secret-key seed-only]" << std::endl;
        std::cout << "  hasSeed=" << seed_only.hasSeed()
                  << " isAxFlushed=" << seed_only.isAxFlushed() << std::endl;

#ifdef DEB_SERIALIZE
        std::ostringstream os_full, os_seed;
        serializeToStream(full, os_full);
        serializeToStream(seed_only, os_seed);
        std::cout << "  serialized size: full=" << os_full.str().size()
                  << " B, seed-only=" << os_seed.str().size() << " B"
                  << std::endl;
#endif

        // The decryptor regenerates 'a' from the seed automatically.
        Message dec_msg(preset);
        dec.decrypt(seed_only, sk, dec_msg);
        std::cout << "  log2 error (auto-expand decrypt) = "
                  << compareMessage(msg, dec_msg) << std::endl;

        // Explicitly materialize 'a' for use in computation, if desired.
        completeCiphertext(seed_only);
        std::cout << "  after completeCiphertext: isAxFlushed="
                  << seed_only.isAxFlushed() << std::endl;
    }

    // ---------------------------------------------------------------------
    // 2. Deterministic encryption with a user-supplied error seed
    // ---------------------------------------------------------------------
    {
        RNGSeed a_seed = SeedGenerator::Gen();
        RNGSeed error_seed = SeedGenerator::Gen();
        auto opt = EncryptOptions()
                       .ASeed(a_seed)
                       .ErrorSeed(error_seed)
                       .SeedOnlyA(true);

        Ciphertext c1(preset), c2(preset);
        enc.encrypt(msg, sk, c1, opt);
        enc.encrypt(msg, sk, c2, opt);
        completeCiphertext(c1);
        completeCiphertext(c2);

        bool identical = (c1.numPoly() == c2.numPoly());
        for (Size p = 0; identical && p < c1.numPoly(); ++p) {
            for (Size u = 0; identical && u < c1[p].size(); ++u) {
                for (Size i = 0; i < get_degree(preset); ++i) {
                    if (c1[p][u][i] != c2[p][u][i]) {
                        identical = false;
                        break;
                    }
                }
            }
        }
        std::cout << "\n[Deterministic error seed]" << std::endl;
        std::cout << "  two encryptions byte-identical: "
                  << (identical ? "yes" : "no") << std::endl;
    }

    // ---------------------------------------------------------------------
    // 3. Public-key seed-only encryption (needs the enc key to expand 'a')
    // ---------------------------------------------------------------------
    {
        KeyGenerator keygen(preset);
        SwitchKey ek = keygen.genEncKey(sk);

        Ciphertext ctxt(preset);
        enc.encrypt(msg, ek, ctxt, EncryptOptions().SeedOnlyA(true));
        std::cout << "\n[Public-key seed-only]" << std::endl;
        std::cout << "  isAxFlushed=" << ctxt.isAxFlushed() << std::endl;

        // a = v*ax + e cannot be regenerated without the encryption key, so the
        // decryptor refuses a still-compressed public-key ciphertext.
        try {
            Message tmp(preset);
            dec.decrypt(ctxt, sk, tmp);
            std::cout << "  unexpected: decrypt succeeded while compressed"
                      << std::endl;
        } catch (const std::exception &e) {
            std::cout << "  decrypt refused (expected): " << e.what()
                      << std::endl;
        }

        enc.completeCiphertext(ctxt, ek); // supply the encryption key
        Message dec_msg(preset);
        dec.decrypt(ctxt, sk, dec_msg);
        std::cout << "  log2 error (after completeCiphertext) = "
                  << compareMessage(msg, dec_msg) << std::endl;
    }

    return 0;
}
