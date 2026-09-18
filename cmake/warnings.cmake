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

function(set_deb_warnings target)
  target_compile_options(
    ${target}
    PRIVATE
      $<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>:
      -Wall
      -Wconversion
      -Wextra
      -Wpedantic
      -Wshadow
      -Wundef
      -Wunused
      -Wvla
      >
      $<$<CXX_COMPILER_ID:MSVC>:
      /W4>)
endfunction()

# Silence all warnings for a third-party target we pull in via CPM. A consumer
# project that includes deb with global warning flags (e.g.
# add_compile_options(-Wall ...) or CMAKE_CXX_FLAGS) leaks those flags into
# every add_subdirectory(), including our dependencies. A target-level -w / /w
# is appended after those global flags and disables the warnings we neither own
# nor can fix, so the dependency stays quiet regardless of who builds deb.
function(set_deb_no_warnings target)
  if(NOT TARGET ${target})
    return()
  endif()
  target_compile_options(
    ${target}
    PRIVATE
      $<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>:-w>
      $<$<CXX_COMPILER_ID:MSVC>:/w>)
endfunction()
