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

#include <random>
using namespace std;
using namespace deb;

int main() {
    // Preparing resources
    Preset preset = PRESET_EMPTY;
    // Retrieve preset with single secret
    for (auto p : Presets) {
        if (getContext(p)->get_num_secret() == 1) {
            preset = p;
            break;
        }
    }
    if (preset == PRESET_EMPTY) {
        std::cerr << "No preset with single secret found." << std::endl;
        return -1;
    }
    std::cout << "Preset: " << getContext(preset)->get_preset_name() << std::endl;
    Encryptor enc(preset); // Create encryptor
    Decryptor dec(preset); // Create decryptor
    Message msg(preset); // Message to be encrypted
    Message decrypted_msg(preset); // Message to hold decrypted data
    Ciphertext ctxt(preset); // Ciphertext to hold encrypted data
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset); // Secret key generation

    // Random message generation
    msg = generateRandomMessage(preset);


    // ---------------------------------------------------------------------
    // Message encryption/decryption with secret key
    // ---------------------------------------------------------------------
    {
        // Basic encryption and decryption
        DebTimer::start("Basic EnDecryption");
        // Use default options: scale=[predefined factor], level=encryption_level, ntt_out=true
        enc.encrypt(msg, sk, ctxt);
        dec.decrypt(ctxt, sk, decrypted_msg);
        DebTimer::end();
        std::cout << "log2 error = " << compareMessage(msg, decrypted_msg) << " bits" << std::endl;
    }

    // Scaled encryption and decryption
    u64 base_bit = utils::bitWidth(getContext(preset)->get_primes()[0]); // Example scale
    Real scale = std::pow(2.0, base_bit - 3);
    {
        auto opt = EncryptOptions().Scale(scale);
        DebTimer::start("Scaled EnDecryption");
        enc.encrypt(msg, sk, ctxt, opt);
        dec.decrypt(ctxt, sk, decrypted_msg, scale);
        DebTimer::end();
        std::cout << "log2 error = " << compareMessage(msg, decrypted_msg) << " bits" << std::endl;
    }

    // Encrypt with custom level
    Size custom_level = getContext(preset)->get_encryption_level() / 2;
    {
        auto opt = EncryptOptions().Level(custom_level);
        DebTimer::start("Custom Level EnDecryption");
        enc.encrypt(msg, sk, ctxt, opt);
        dec.decrypt(ctxt, sk, decrypted_msg);
        DebTimer::end();
        std::cout << "log2 error = " << compareMessage(msg, decrypted_msg) << " bits" << std::endl;
    }
    // Encrypt with iNTT output
    {
        auto opt = EncryptOptions().NttOut(false);
        DebTimer::start("iNTT Output EnDecryption");
        enc.encrypt(msg, sk, ctxt, opt);
        dec.decrypt(ctxt, sk, decrypted_msg);
        DebTimer::end();
        std::cout << "log2 error = " << compareMessage(msg, decrypted_msg) << " bits" << std::endl;
    }

    // Encrypt with all custom options
    {
        DebTimer::start("All Custom Options EnDecryption");
        enc.encrypt(msg, sk, ctxt, EncryptOptions().Scale(scale).Level(custom_level).NttOut(false));
        dec.decrypt(ctxt, sk, decrypted_msg, scale);
        DebTimer::end();
        std::cout << "log2 error = " << compareMessage(msg, decrypted_msg) << " bits" << std::endl;
    }

    // ---------------------------------------------------------------------
    // Coefficient message encryption/decryption with secret key
    // ---------------------------------------------------------------------
    CoeffMessage cmsg = generateRandomCoeffMessage(preset); // CoeffMessage to be encrypted
    CoeffMessage decrypted_cmsg(preset); // CoeffMessage to hold decrypted data

    // Basic encryption and decryption
    // Use default options: scale=[predefined factor], level=encryption_level, ntt_out=true
    {
        DebTimer::start("Basic Coeff EnDecryption");
        enc.encrypt(cmsg, sk, ctxt);
        dec.decrypt(ctxt, sk, decrypted_cmsg);
        DebTimer::end();
        std::cout << "log2 error = " << compareCoeff(cmsg, decrypted_cmsg) << " bits" << std::endl;
    }


    // Encrypt with all custom options
    {
        DebTimer::start("All Custom Options Coeff EnDecryption");
        enc.encrypt(cmsg, sk, ctxt, EncryptOptions().Scale(scale).Level(custom_level).NttOut(false));
        dec.decrypt(ctxt, sk, decrypted_cmsg, scale);
        DebTimer::end();
        std::cout << "log2 error = " << compareMessage(msg, decrypted_msg) << " bits" << std::endl;
    }

    // ---------------------------------------------------------------------
    // (Coefficient) Message encryption with encryption key
    // ---------------------------------------------------------------------
    // Generate encryption key from secret key
    KeyGenerator keygen(sk);
    SwitchKey ek = keygen.genEncKey(sk);

    // Basic encryption with encryption key
    {
        DebTimer::start("Encryption with EncKey");
        enc.encrypt(msg, ek, ctxt);
        dec.decrypt(ctxt, sk, decrypted_msg);
        DebTimer::end();
        std::cout << "log2 error = " << compareMessage(msg, decrypted_msg) << " bits" << std::endl;
    }

    // Basic coefficient encryption with encryption key
    {
        DebTimer::start("Coeff Encryption with EncKey");
        enc.encrypt(cmsg, ek, ctxt);
        dec.decrypt(ctxt, sk, decrypted_cmsg);
        DebTimer::end();
        std::cout << "log2 error = " << compareCoeff(cmsg, decrypted_cmsg) << " bits" << std::endl;
    }

    // Encrypt with all custom options
    {
        DebTimer::start("All Custom Options EnDecryption with EncKey");
        enc.encrypt(msg, ek, ctxt, EncryptOptions().Scale(scale).Level(custom_level).NttOut(false));
        dec.decrypt(ctxt, sk, decrypted_msg, scale);
        DebTimer::end();
        std::cout << "log2 error = " << compareMessage(msg, decrypted_msg) << " bits" << std::endl;
    }

    // Encrypt with all custom options
    {
        DebTimer::start("All Custom Options Coeff EnDecryption with EncKey");
        enc.encrypt(cmsg, ek, ctxt, EncryptOptions().Scale(scale).Level(custom_level).NttOut(false));
        dec.decrypt(ctxt, sk, decrypted_cmsg, scale);
        DebTimer::end();
        std::cout << "log2 error = " << compareCoeff(cmsg, decrypted_cmsg) << " bits" << std::endl;
    }

    return 0;
}
