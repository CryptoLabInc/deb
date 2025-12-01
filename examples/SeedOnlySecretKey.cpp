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

using namespace std;
using namespace deb;

int main() {
    Preset preset = static_cast<Preset>(0);
    std::cout << "Preset: " << getContext(preset)->get_preset_name() << std::endl;

    // Generate seed for secret key
    RNGSeed sk_seed = SeedGenerator::Gen();
    // Seed only secret key
    SecretKey seed_only_sk(preset, sk_seed);

    // Serialize seed only secret key
    ostringstream os;
    serializeToStream(seed_only_sk, os);
    std::cout << "Serialized secret key size (seed only): " << os.str().size() << " bytes" << std::endl;

    // Generate coeff from the seed
    SecretKey coeff_only_sk(preset, false);
    SecretKeyGenerator::GenCoeffInplace(preset, coeff_only_sk.coeffs(), sk_seed);

    // Serialize coeff only secret key
    os = ostringstream(); // Clear the stream
    serializeToStream(coeff_only_sk, os);
    std::cout << "Serialized secret key size (coeff only): " << os.str().size() << " bytes" << std::endl;

#if defined(DEB_RESOURCE_CHECK) && defined(NDEBUG)
    try {
        KeyGenerator keygen(preset);
        SwitchKey enckey = keygen.genEncKey(seed_only_sk);
    } catch (...) {
        std::cout << "Cannot use seed only secret key to encrypt and keygen (serialize only)" << std::endl;
    }

    try {
        KeyGenerator keygen(preset);
        SwitchKey enckey = keygen.genEncKey(coeff_only_sk);
    } catch (...) {
        std::cout << "Cannot use coeff only secret key to encrypt and keygen (serialize only)" << std::endl;
    }
#endif

    // Generate full secret key
    completeSecretKey(seed_only_sk);
    completeSecretKey(coeff_only_sk);

    // Now both secret keys can be used for encryption and keygeneration
    KeyGenerator keygen(preset);
    SwitchKey enckey1 = keygen.genEncKey(seed_only_sk);
    SwitchKey enckey2 = keygen.genEncKey(coeff_only_sk);

    Message msg = generateRandomMessage(preset);
    Encryptor enc(preset);
    Ciphertext ctxt1(preset), ctxt2(preset);
    enc.encrypt(msg, enckey1, ctxt1);
    enc.encrypt(msg, enckey2, ctxt2);

    Decryptor dec(preset);
    Message dec_msg1(preset), dec_msg2(preset);

    dec.decrypt(ctxt1, seed_only_sk, dec_msg1);
    dec.decrypt(ctxt2, coeff_only_sk, dec_msg2);

    std::cout << "log error1: " << compareMessage(msg, dec_msg1) << std::endl;
    std::cout << "log error2: " << compareMessage(msg, dec_msg2) << std::endl;
    return 0;
}
