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

#include <random>
using namespace deb;

namespace {

// Produces a Message sized to the polynomial degree (not num_slots) with
// imaginary parts zero — the input shape the real-encryption path expects.
Message generateRandomRealMessage(const Preset preset) {
    static std::mt19937 eng(std::random_device{}());
    std::uniform_real_distribution<Real> dist(-1.0, 1.0);
    Message msg(get_degree(preset));
    for (size_t i = 0; i < msg.size(); ++i) {
        msg[i].real(dist(eng));
        msg[i].imag(0.0);
    }
    return msg;
}

} // namespace

int main() {
    // Real encryption requires a preset whose primes are 4N-friendly. The
    // bundled FGbD12L0 preset is one such configuration.
    Preset preset = PRESET_EMPTY;
    for (auto p : Presets) {
        if (std::string(get_preset_name(p)) == "FGbD12L0") {
            preset = p;
            break;
        }
    }
    if (preset == PRESET_EMPTY) {
        std::cerr << "No real-friendly preset (FGbD12L0) found." << std::endl;
        return -1;
    }
    std::cout << "Preset: " << get_preset_name(preset) << std::endl;

    // Build Encryptor / Decryptor with the real_encrypt / real_decrypt flag
    // so each ModArith eagerly initializes its cyclic NTT object.
    Encryptor enc(preset);
    Decryptor dec(preset);

    // Real encryption uses full-degree real-valued messages (not num_slots).
    Message msg(get_degree(preset));          // Message to be encrypted
    Message decrypted_msg(get_degree(preset)); // Message to hold decrypted data
    Ciphertext ctxt(preset);                   // Ciphertext to hold encrypted data

    // Secret key must be generated in CYCLIC NTT mode so its NTT-domain
    // representation matches the ciphertext produced by real encryption.
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset, std::nullopt,
                                                    utils::NTTType::CYCLIC);

    // Random real-valued message (imag == 0 for every slot).
    msg = generateRandomRealMessage(preset);

    // ---------------------------------------------------------------------
    // Message encryption/decryption with secret key (real)
    // ---------------------------------------------------------------------
    {
        // Basic real encryption/decryption.
        DebTimer::start("Basic Real EnDecryption");
        enc.encrypt(msg, sk, ctxt, EncryptOptions().RealEncrypt(true));
        dec.decrypt(ctxt, sk, decrypted_msg);
        DebTimer::end();
        std::cout << "log2 error = " << compareMessage(msg, decrypted_msg) << " bits" << std::endl;
    }

    // Scaled real encryption/decryption.
    u64 base_bit = utils::bitWidth(get_primes(preset)[0]);
    Real scale = std::pow(2.0, base_bit - 3);
    {
        auto opt = EncryptOptions().Scale(scale).RealEncrypt(true);
        DebTimer::start("Scaled Real EnDecryption");
        enc.encrypt(msg, sk, ctxt, opt);
        dec.decrypt(ctxt, sk, decrypted_msg, scale);
        DebTimer::end();
        std::cout << "log2 error = " << compareMessage(msg, decrypted_msg) << " bits" << std::endl;
    }

    // Real encryption at a custom level.
    Size custom_level = get_encryption_level(preset) / 2;
    {
        auto opt = EncryptOptions().Level(custom_level).RealEncrypt(true);
        DebTimer::start("Custom Level Real EnDecryption");
        enc.encrypt(msg, sk, ctxt, opt);
        dec.decrypt(ctxt, sk, decrypted_msg);
        DebTimer::end();
        std::cout << "log2 error = " << compareMessage(msg, decrypted_msg) << " bits" << std::endl;
    }

    // Real encryption with iNTT (coefficient-domain) output.
    {
        auto opt = EncryptOptions().NTTOut(false).RealEncrypt(true);
        DebTimer::start("iNTT Output Real EnDecryption");
        enc.encrypt(msg, sk, ctxt, opt);
        dec.decrypt(ctxt, sk, decrypted_msg);
        DebTimer::end();
        std::cout << "log2 error = " << compareMessage(msg, decrypted_msg) << " bits" << std::endl;
    }

    // All custom options combined.
    {
        DebTimer::start("All Custom Options Real EnDecryption");
        enc.encrypt(msg, sk, ctxt,
                    EncryptOptions().Scale(scale).Level(custom_level).NTTOut(false).RealEncrypt(true));
        dec.decrypt(ctxt, sk, decrypted_msg, scale);
        DebTimer::end();
        std::cout << "log2 error = " << compareMessage(msg, decrypted_msg) << " bits" << std::endl;
    }

    // ---------------------------------------------------------------------
    // Coefficient message encryption/decryption with secret key (real)
    // ---------------------------------------------------------------------
    CoeffMessage cmsg = generateRandomCoeffMessage(preset);
    CoeffMessage decrypted_cmsg(preset);

    {
        DebTimer::start("Basic Real Coeff EnDecryption");
        enc.encrypt(cmsg, sk, ctxt, EncryptOptions().RealEncrypt(true));
        dec.decrypt(ctxt, sk, decrypted_cmsg);
        DebTimer::end();
        std::cout << "log2 error = " << compareCoeff(cmsg, decrypted_cmsg) << " bits" << std::endl;
    }

    {
        DebTimer::start("All Custom Options Real Coeff EnDecryption");
        enc.encrypt(cmsg, sk, ctxt,
                    EncryptOptions().Scale(scale).Level(custom_level).NTTOut(false).RealEncrypt(true));
        dec.decrypt(ctxt, sk, decrypted_cmsg, scale);
        DebTimer::end();
        std::cout << "log2 error = " << compareCoeff(cmsg, decrypted_cmsg) << " bits" << std::endl;
    }

    // ---------------------------------------------------------------------
    // (Coefficient) Message encryption with encryption key (real)
    // ---------------------------------------------------------------------
    KeyGenerator keygen(preset);
    SwitchKey ek = keygen.genEncKey(sk);

    {
        DebTimer::start("Real Encryption with EncKey");
        enc.encrypt(msg, ek, ctxt, EncryptOptions().RealEncrypt(true));
        dec.decrypt(ctxt, sk, decrypted_msg);
        DebTimer::end();
        std::cout << "log2 error = " << compareMessage(msg, decrypted_msg) << " bits" << std::endl;
    }

    {
        DebTimer::start("Real Coeff Encryption with EncKey");
        enc.encrypt(cmsg, ek, ctxt, EncryptOptions().RealEncrypt(true));
        dec.decrypt(ctxt, sk, decrypted_cmsg);
        DebTimer::end();
        std::cout << "log2 error = " << compareCoeff(cmsg, decrypted_cmsg) << " bits" << std::endl;
    }

    {
        DebTimer::start("All Custom Options Real EnDecryption with EncKey");
        enc.encrypt(msg, ek, ctxt,
                    EncryptOptions().Scale(scale).Level(custom_level).NTTOut(false).RealEncrypt(true));
        dec.decrypt(ctxt, sk, decrypted_msg, scale);
        DebTimer::end();
        std::cout << "log2 error = " << compareMessage(msg, decrypted_msg) << " bits" << std::endl;
    }

    {
        DebTimer::start("All Custom Options Real Coeff EnDecryption with EncKey");
        enc.encrypt(cmsg, ek, ctxt,
                    EncryptOptions().Scale(scale).Level(custom_level).NTTOut(false).RealEncrypt(true));
        dec.decrypt(ctxt, sk, decrypted_cmsg, scale);
        DebTimer::end();
        std::cout << "log2 error = " << compareCoeff(cmsg, decrypted_cmsg) << " bits" << std::endl;
    }

    return 0;
}
