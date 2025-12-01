# ~~~
# Copyright 2025 CryptoLab, Inc.
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
target_link_libraries(deb-benchmark PRIVATE deb_obj deb_DevHeader
                                            benchmark::benchmark_main)
set_my_project_warnings(deb-benchmark)
