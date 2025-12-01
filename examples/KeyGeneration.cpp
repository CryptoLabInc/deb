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
    Preset preset;
    for(auto p : Presets) {
        // fine 0 level preset
        if(getContext(p)->get_num_base() == 1 && getContext(p)->get_num_qp() == 0) {
            preset = p;
            break;
        }
    }
    std::cout << "Preset: " << getContext(preset)->get_preset_name() << std::endl;

    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    KeyGenerator keygen(sk);

    // Generate encryption key
    {
        SwitchKey enckey(preset, SwitchKeyKind::SWK_ENC);
        DebTimer::start("Encryption Key Generation");
        keygen.genEncKeyInplace(enckey); // inplace keygen
        DebTimer::end();

        SwitchKey enckey2 = keygen.genEncKey(); // outplace keygen
    }

    // Generate multiplication key
    {
        SwitchKey mulkey(preset, SwitchKeyKind::SWK_MULT);
        DebTimer::start("Multiplication Key Generation");
        keygen.genMultKeyInplace(mulkey); // inplace keygen
        DebTimer::end();

        SwitchKey mulkey2 = keygen.genMultKey(); // outplace keygen
    }

    // Generate conjugation key
    {
        SwitchKey conjkey(preset, SwitchKeyKind::SWK_CONJ);
        DebTimer::start("Conjugation Key Generation");
        keygen.genConjKeyInplace(conjkey); // inplace keygen
        DebTimer::end();

        SwitchKey conjkey2 = keygen.genConjKey(); // outplace keygen
    }

    // Generate left rotation key
    Size rot = 1;
    {
        SwitchKey lrotkey(preset, SwitchKeyKind::SWK_ROT);
        DebTimer::start("Left Rotation Key Generation");
        keygen.genLeftRotKeyInplace(rot, lrotkey); // inplace keygen
        DebTimer::end();

        std::cout << "rotation index: " << rot << std::endl;
        SwitchKey lrotkey2 = keygen.genLeftRotKey(rot); // outplace keygen
    }

    // Generate right rotation key
    {
        SwitchKey rrotkey(preset, SwitchKeyKind::SWK_ROT);
        DebTimer::start("Right Rotation Key Generation");
        keygen.genRightRotKeyInplace(rot, rrotkey); // inplace keygen
        DebTimer::end();

        SwitchKey rrotkey2 = keygen.genRightRotKey(rot); // outplace keygen
    }

    // Generate automorphism key
    {
        SwitchKey autokey(preset, SwitchKeyKind::SWK_AUTO);
        DebTimer::start("Automorphism Key Generation");
        keygen.genAutoKeyInplace(rot, autokey); // inplace keygen
        DebTimer::end();

        SwitchKey autokey2 = keygen.genAutoKey(rot); // outplace keygen
    }

    // Generate composition key
    SecretKey sk_from = SecretKeyGenerator::GenSecretKey(preset);
    {
        SwitchKey composekey(preset, SwitchKeyKind::SWK_COMPOSE);
        DebTimer::start("Composition Key Generation");
        keygen.genComposeKeyInplace(sk_from, composekey); // inplace keygen
        DebTimer::end();

        SwitchKey composekey2 = keygen.genComposeKey(sk_from); // outplace keygen
    }

    // Generate decomposition key
    SecretKey sk_to = SecretKeyGenerator::GenSecretKey(preset);
    {
        SwitchKey decompkey(preset, SwitchKeyKind::SWK_DECOMPOSE);
        DebTimer::start("Decomposition Key Generation");
        keygen.genDecomposeKeyInplace(sk_to, decompkey); // inplace keygen
        DebTimer::end();

        SwitchKey decompkey2 = keygen.genDecomposeKey(sk_to); // outplace keygen
    }

    // Generate decomposition key with switching context
    {
        Preset preset_swk = preset; // for simplicity, use the same preset
        SwitchKey decompkey_swk(preset_swk, SwitchKeyKind::SWK_DECOMPOSE);
        DebTimer::start("Decomposition Key Generation with switching context");
        keygen.genDecomposeKeyInplace(preset_swk, sk_to, decompkey_swk); // inplace keygen
        DebTimer::end();

        SwitchKey decompkey_swk2 = keygen.genDecomposeKey(preset_swk, sk_to); // outplace keygen
    }

    // Generate modpack keys
    {
        std::vector<SwitchKey> modpack_keys;
        modpack_keys.push_back(
            SwitchKey(preset, SwitchKeyKind::SWK_MODPACK));
        DebTimer::start("ModPack Key Bundle Generation");
        keygen.genModPackKeyBundleInplace(sk_from, sk_to, modpack_keys); // inplace keygen
        DebTimer::end();

        auto modpack_keys2 = keygen.genModPackKeyBundle(sk_from, sk_to); // outplace keygen
    }

    // Generate self modpack key with pad_rank
    {
        const Size pad_rank = 1U << (getContext(preset)->get_log_degree() / 2);
        const Size num_p = getContext(preset)->get_num_p();
        SwitchKey self_modkey(preset, SwitchKeyKind::SWK_MODPACK_SELF);
        self_modkey.addAx(num_p, pad_rank, true);
        self_modkey.addBx(num_p, pad_rank * getContext(preset)->get_num_secret(), true);
        DebTimer::start("Self ModPack Key Bundle Generation");
        keygen.genModPackKeyBundleInplace(pad_rank, self_modkey); // inplace keygen
        DebTimer::end();

        self_modkey = keygen.genModPackKeyBundle(pad_rank); // outplace keygen
    }

    return 0;
}
