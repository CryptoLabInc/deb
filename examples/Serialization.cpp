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

#include <filesystem>
#include <fstream>

using namespace std;
using namespace deb;

int main() {
    // Define presets to test
    Preset preset;
    for (auto p : Presets) {
        if (getContext(p)->get_num_secret() == 1) {
            preset = p;
            break;
        }
    }
    std::cout << "Preset: " << getContext(preset)->get_preset_name() << std::endl;

    // Generate resources
    Message msg = generateRandomMessage(preset);
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    Encryptor encryptor(preset);
    Decryptor decryptor(preset);
    KeyGenerator keygen(sk);

    std::string tmp_dir = "./example_data/";
    std::filesystem::create_directories(tmp_dir);


    // Serialize message, sk, key, ciphertext
    {
        SwitchKey enckey = keygen.genEncKey();
        Ciphertext cipher(preset);
        encryptor.encrypt(msg, enckey, cipher);

        ofstream of(tmp_dir + "serialize_example1.bin", ios::binary);
        serializeToStream(msg, of);
        serializeToStream(sk, of);
        serializeToStream(enckey, of);
        serializeToStream(cipher, of);
        of.close();

        ifstream inf(tmp_dir + "serialize_example1.bin", ios::binary);
        Message msg2(preset);
        SecretKey sk2(preset);
        SwitchKey enckey2(preset, SWK_ENC);
        Ciphertext cipher2(preset);
        deserializeFromStream(inf, msg2);
        deserializeFromStream(inf, sk2);
        deserializeFromStream(inf, enckey2);
        deserializeFromStream(inf, cipher2);
        inf.close();

        // Decrypt and verify
        Message msg_decrypted(preset);
        decryptor.decrypt(cipher, sk, msg_decrypted);
        std::cout << "before serial error: " << compareMessage(msg, msg_decrypted) << "bit" << std::endl;

        decryptor.decrypt(cipher2, sk2, msg_decrypted);
        std::cout << "after serial error: " << compareMessage(msg, msg_decrypted) << "bit" << std::endl;

        std::filesystem::remove(tmp_dir + "serialize_example1.bin");
    }

    return 0;
}
