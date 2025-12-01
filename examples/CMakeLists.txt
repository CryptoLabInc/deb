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

add_library(example_utils OBJECT ExampleUtils.cpp)
target_link_libraries(example_utils PRIVATE ${PROJECT_NAME}_obj
                                            ${PROJECT_NAME}_DevHeader)

set(${PROJECT_NAME}_example example_utils ${PROJECT_NAME}_obj
                            ${PROJECT_NAME}_DevHeader)

# Example targets
add_executable(EnDecryption EnDecryption.cpp)
target_link_libraries(EnDecryption PRIVATE ${${PROJECT_NAME}_example})

add_executable(EnDecryption-MultiSecret EnDecryption-MultiSecret.cpp)
target_link_libraries(EnDecryption-MultiSecret
                      PRIVATE ${${PROJECT_NAME}_example})

add_executable(SeedOnlySecretKey SeedOnlySecretKey.cpp)
target_link_libraries(SeedOnlySecretKey PRIVATE ${${PROJECT_NAME}_example})

add_executable(Serialization Serialization.cpp)
target_link_libraries(Serialization PRIVATE ${${PROJECT_NAME}_example})

add_executable(KeyGeneration KeyGeneration.cpp)
target_link_libraries(KeyGeneration PRIVATE ${${PROJECT_NAME}_example})
