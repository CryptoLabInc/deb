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

function(set_my_project_warnings target)
  target_compile_options(
    ${target}
    PRIVATE
      $<$<OR:$<C_COMPILER_ID:Clang>,$<C_COMPILER_ID:AppleClang>,$<C_COMPILER_ID:GNU>>:
      -Wall
      -Wconversion
      -Wextra
      -Wpedantic
      -Wshadow
      -Wundef
      -Wunused
      -Wvla
      >
      $<$<C_COMPILER_ID:MSVC>:
      /W4>)
endfunction()
