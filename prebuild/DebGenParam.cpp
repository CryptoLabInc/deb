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

// DebGenParam.cpp
// Build: g++ -std=c++17 -O2 DebGenParam.cpp -o DebGenParam
// Usage: ./DebGenParam input.json output.hpp PRESET1 PRESET2 ...

#include <filesystem>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "DebPreComputeUtils.hpp"

int main(int argc, char **argv) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0]
                  << " <INPUT_JSON> <OUTPUT_HPP> <PRESET_LISTS>\n";
        return 1;
    }
    const std::string in_json = argv[1];
    std::unordered_set<std::string> preset_list;
    for (int i = 3; i < argc; ++i) {
        preset_list.insert(argv[i]);
    }
    const std::string out_hpp = argv[2];

    std::ifstream is(in_json);
    if (!is) {
        std::cerr << "Failed to open input: " << in_json << "\n";
        return 1;
    }

    json root;
    is >> root;
    if (!root.is_array()) {
        std::cerr << "Top-level JSON must be an array\n";
        return 1;
    }

    std::unordered_map<std::string, RawPreset> raw_by_name;
    for (const auto &item : root) {
        if (!item.is_object())
            continue;
        if (!item.contains("NAME")) {
            // comment object or non-preset, skip
            continue;
        }
        if (item.contains("LOG_BP_SIZE")) {
            // Custom preset
            CustomP r = parse_custom_preset(item);
            if (r.NAME.empty())
                continue;
            if (raw_by_name.count(r.NAME)) {
                std::cerr << "Duplicate NAME: " << r.NAME << "\n";
                return 1;
            }
            raw_by_name.emplace(r.NAME, std::move(r));
        } else {
            PresetP r = parse_raw_preset(item);
            if (r.NAME.empty())
                continue;
            if (raw_by_name.count(r.NAME)) {
                std::cerr << "Duplicate NAME: " << r.NAME << "\n";
                return 1;
            }
            // If PARENT missing, spec says default is Self
            if (!r.has_PARENT) {
                r.PARENT = r.NAME;
                r.has_PARENT = true;
            }
            raw_by_name.emplace(r.NAME, std::move(r));
        }
    }

    // Resolve all
    std::unordered_map<std::string, FinalPreset> memo;
    std::unordered_set<std::string> visiting;
    std::vector<FinalPreset> finals;
    std::unordered_set<std::string> parent_presets;

    for (const auto &kv : raw_by_name) {
        const std::string &name = kv.first;
        if (!preset_list.count("ALL") && !preset_list.count(name))
            continue;
        FinalPreset p = resolve_one(name, raw_by_name, memo, visiting);
        finals.push_back(std::move(p));
        parent_presets.insert(memo[name].PARENT);
    }
    for (const auto &pname : parent_presets) {
        if (!pname.empty() && !memo.count(pname)) {
            // ensure all parents are also included
            FinalPreset p = resolve_one(pname, raw_by_name, memo, visiting);
            finals.push_back(std::move(p));
        }
    }

    // sort by NAME for deterministic header
    std::sort(finals.begin(), finals.end(),
              [](const FinalPreset &a, const FinalPreset &b) {
                  return a.NAME < b.NAME;
              });

    try {
        write_header(out_hpp, finals);
    } catch (const std::exception &e) {
        std::cerr << "Error writing header: " << e.what() << "\n";
        return 1;
    }

    std::cout << "Generated: " << out_hpp << " (" << finals.size()
              << " presets)\n";

    return 0;
}
