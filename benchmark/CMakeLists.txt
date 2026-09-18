# ~~~
# Copyright 2026 CryptoLab, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ~~~

cpmaddpackage(URI "gh:google/benchmark@1.9.4" OPTIONS
              "BENCHMARK_ENABLE_TESTING Off")

add_executable(deb-benchmark benchmark.cpp)
target_link_libraries(deb-benchmark PRIVATE deb benchmark::benchmark_main)

# Standalone A/B benchmark: compile-time-preset (templated) vs runtime-preset.
# No google/benchmark dependency, so it builds even offline.
add_executable(deb-bench-ct-vs-rt bench_ct_vs_rt.cpp)
target_link_libraries(deb-bench-ct-vs-rt PRIVATE deb)

enable_language(C)
# BLAKE3 is used only by the benchmark below, never by the library, so none of
# it belongs in the install tree. Its install rules are also broken for a
# subproject build: upstream writes libblake3.pc into its own binary dir but
# installs it from ${CMAKE_BINARY_DIR} (the top-level one), so `cmake --install`
# fails on a file that was never there. There is no BLAKE3_INSTALL option to
# turn this off, and EXCLUDE_FROM_ALL does not suppress install() rules, so the
# rules are skipped for the duration of the subdirectory instead.
set(_deb_skip_install_backup ${CMAKE_SKIP_INSTALL_RULES})
set(CMAKE_SKIP_INSTALL_RULES TRUE)
cpmaddpackage(
  NAME
  blake3
  GITHUB_REPOSITORY
  BLAKE3-team/BLAKE3
  GIT_TAG
  1.8.1
  SOURCE_SUBDIR
  c)
set(CMAKE_SKIP_INSTALL_RULES ${_deb_skip_install_backup})
unset(_deb_skip_install_backup)
# CMAKE_SKIP_INSTALL_RULES suppresses the generated cmake_install.cmake for that
# directory, but this directory's own script still include()s it, so leave an
# empty one in its place.
file(
  WRITE ${blake3_BINARY_DIR}/cmake_install.cmake
  "# BLAKE3 is a benchmark-only dependency and is intentionally not installed.\n"
)

add_executable(deb-benchmark-blake3 benchmark_blake3.cpp)
target_link_libraries(deb-benchmark-blake3
                      PRIVATE deb benchmark::benchmark_main BLAKE3::blake3)
