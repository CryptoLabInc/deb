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

include(CPM)

cpmaddpackage(
  NAME
  alea
  GITHUB_REPOSITORY
  CryptoLabInc/alea
  GIT_TAG
  v0.1.6
  OPTIONS
  "ALEA_BUILD_TEST OFF"
  "ALEA_BUILD_DOXYGEN ${DEB_BUILD_DOXYGEN}"
  "ALEA_INSTALL ${DEB_INSTALL_ALEA}"
  "BUILD_SHARED_LIBS ${BUILD_SHARED_LIBS}")

cpmaddpackage(
  NAME
  flatbuffers
  GITHUB_REPOSITORY
  google/flatbuffers
  GIT_TAG
  v25.2.10
  OPTIONS
  "FLATBUFFERS_BUILD_TESTS OFF"
  "FLATBUFFERS_INSTALL ${DEB_INSTALL_FLATBUFFERS}"
  "FLATBUFFERS_BUILD_SHAREDLIB ${BUILD_SHARED_LIBS}")

set(flatbuffers_SOURCE_DIR
    ${flatbuffers_SOURCE_DIR}
    CACHE PATH "" FORCE)
