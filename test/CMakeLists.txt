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

# Add a gtest target to ctest. Make the target report a xml file.
function(add_gtest_target_to_ctest target)
  add_test(NAME "${target}" COMMAND "${target}"
                                    --gtest_output=xml:${target}.xml)
endfunction()

cpmaddpackage(
  NAME
  googletest
  GITHUB_REPOSITORY
  google/googletest
  GIT_TAG
  v1.17.0
  OPTIONS
  "INSTALL_GTEST OFF"
  "BUILD_GMOCK OFF")

# ---------------------------------------------------------------------------

set(deb_test deb_obj deb_DevHeader gtest_main)
# Ntt Test
add_executable(NTT-test NTT-test.cpp)
target_link_libraries(NTT-test PRIVATE ${deb_test})
add_gtest_target_to_ctest(NTT-test)

# EnDecryption Test
add_executable(EnDecryption-test EnDecryption-test.cpp)
target_link_libraries(EnDecryption-test PRIVATE ${deb_test})
add_gtest_target_to_ctest(EnDecryption-test)

# Serialize Test
add_executable(Serialize-test Serialize-test.cpp)
target_link_libraries(Serialize-test PRIVATE ${deb_test})
add_gtest_target_to_ctest(Serialize-test)

# KeyGen Test
add_executable(KeyGen-test KeyGen-test.cpp)
target_link_libraries(KeyGen-test PRIVATE ${deb_test})
add_gtest_target_to_ctest(KeyGen-test)
