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

set(DEB_PARAMETER_JSON
    ${PRE_BUILD_SRC_DIR}/DebParamPreset.json
    CACHE STRING "Path to the parameter JSON file.")
set(PRESET_LIST
    "ALL" # Default equivalent to "FGbD12L0;FGb;FGbMS;"
    CACHE STRING "List of enabled presets. Use 'ALL' to enable all presets.")

set(FLATBUFFER_SCHEMAS ${PRE_BUILD_SRC_DIR}/DebFBType.fbs)
set(GEN_PARAM_H ${PRE_BUILD_DIR}/DebParam.hpp)

set(flatbuffers_SOURCE_DIR
    "${flatbuffers_SOURCE_DIR}"
    CACHE PATH "flatbuffers source dir (injected by parent)")

if(CMAKE_CROSSCOMPILING)
  set(HOST_CC
      "/usr/bin/gcc"
      CACHE STRING "")
  set(HOST_CXX
      "/usr/bin/g++"
      CACHE STRING "")

  include(ExternalProject)

  set(HOST_FLATC_ROOT "${CMAKE_BINARY_DIR}/_host_flatc")
  set(HOST_FLATC_BDIR "${HOST_FLATC_ROOT}/build")

  ExternalProject_Add(
    host_flatc
    PREFIX "${HOST_FLATC_ROOT}"
    SOURCE_DIR "${flatbuffers_SOURCE_DIR}"
    DOWNLOAD_COMMAND ""
    BINARY_DIR "${HOST_FLATC_BDIR}"
    CMAKE_ARGS -DCMAKE_BUILD_TYPE=Release
               -DCMAKE_TOOLCHAIN_FILE=
               -DANDROID=OFF
               -DCMAKE_C_COMPILER=${HOST_CC}
               -DCMAKE_CXX_COMPILER=${HOST_CXX}
               -DFLATBUFFERS_BUILD_FLATC=ON
               -DFLATBUFFERS_BUILD_TESTS=OFF
               -DFLATBUFFERS_BUILD_FLATLIB=OFF
               -DFLATBUFFERS_BUILD_SHAREDLIB=OFF
               -DFLATBUFFERS_INSTALL=OFF
    BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --target flatc
    INSTALL_COMMAND
      ${CMAKE_COMMAND} -E make_directory ${HOST_FLATC_BDIR}/bin &&
      ${CMAKE_COMMAND} -E copy <BINARY_DIR>/flatc ${HOST_FLATC_BDIR}/bin/flatc)
  ExternalProject_Add_StepTargets(host_flatc install)

  if(WIN32)
    set(HOST_FLATC_BIN "${HOST_FLATC_BDIR}/flatc.exe")
  else()
    set(HOST_FLATC_BIN "${HOST_FLATC_BDIR}/flatc")
  endif()

  message(STATUS "Host flatc binary: ${HOST_FLATC_BIN}")

  add_executable(flatc_host IMPORTED GLOBAL)
  set_target_properties(flatc_host PROPERTIES IMPORTED_LOCATION
                                              "${HOST_FLATC_BIN}")
  add_dependencies(flatc_host host_flatc-install)
  set(FLATC_EXECUTABLE $<TARGET_FILE:flatc_host>)

  set(HOST_GENPARAM_DIR ${CMAKE_BINARY_DIR}/_host_genparam_build)
  set(HOST_GENPARAM_BIN ${HOST_GENPARAM_DIR}/GenParam)

  # Configure
  add_custom_command(
    OUTPUT ${HOST_GENPARAM_DIR}/CMakeCache.txt
    COMMAND
      ${CMAKE_COMMAND} -S ${PRE_BUILD_DIR} -B ${HOST_GENPARAM_DIR}
      -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE= -DANDROID=OFF
      -DCMAKE_C_COMPILER=${HOST_CC} -DCMAKE_CXX_COMPILER=${HOST_CXX}
      -DCMAKE_CXX_STANDARD=17 -DCMAKE_CXX_STANDARD_REQUIRED=ON
      -DPREBUILD_HOST_MODE=ON -DPRE_BUILD_DIR=${PRE_BUILD_DIR}
    COMMENT "Configuring host GenParam with GCC"
    VERBATIM COMMAND_EXPAND_LISTS)

  # Build+Install
  add_custom_command(
    OUTPUT ${HOST_GENPARAM_BIN}
    COMMAND ${CMAKE_COMMAND} --build ${HOST_GENPARAM_DIR} --config Release
    DEPENDS ${HOST_GENPARAM_DIR}/CMakeCache.txt
    COMMENT "Building+Installing host GenParam"
    VERBATIM)

  add_custom_target(host_genparam ALL DEPENDS ${HOST_GENPARAM_BIN})
  set(GENPARAM_CMD ${HOST_GENPARAM_BIN})

else()
  set(FLATC_EXECUTABLE $<TARGET_FILE:flatc>)

  add_executable(GenParam ${PRE_BUILD_SRC_DIR}/DebGenParam.cpp)
  target_include_directories(
    GenParam PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../external/nlohmann_json)
  set(GENPARAM_CMD $<TARGET_FILE:GenParam>)

endif()

if(NOT PREBUILD_HOST_MODE)
  foreach(fbs_file ${FLATBUFFER_SCHEMAS})
    get_filename_component(fname ${fbs_file} NAME_WE)
    set(generated_header ${PRE_BUILD_DIR}/${fname}.h)

    add_custom_command(
      OUTPUT ${generated_header}
      COMMAND ${FLATC_EXECUTABLE} --cpp -o ${PRE_BUILD_DIR} ${fbs_file}
      COMMAND ${CMAKE_COMMAND} -E rename ${PRE_BUILD_DIR}/${fname}_generated.h
              ${generated_header}
      DEPENDS ${FLATC_EXECUTABLE} ${fbs_file}
      COMMENT "Generating cpp flatbuffer from ${fbs_file}")

    list(APPEND GENERATED_HEADERS ${generated_header})
  endforeach()

  message(STATUS "Preset list: ${PRESET_LIST}")
  set_source_files_properties(${GEN_PARAM_H} PROPERTIES GENERATED TRUE)
  add_custom_command(
    OUTPUT ${GEN_PARAM_H}
    COMMAND ${GENPARAM_CMD} ${DEB_PARAMETER_JSON} ${GEN_PARAM_H} ${PRESET_LIST}
    DEPENDS ${GENPARAM_CMD} ${DEB_PARAMETER_JSON}
            $<$<BOOL:${CMAKE_CROSSCOMPILING}>:host_genparam>
            $<$<NOT:$<BOOL:${CMAKE_CROSSCOMPILING}>>:GenParam>
    COMMENT "Generating ${GEN_PARAM_H} via GenParam"
    VERBATIM COMMAND_EXPAND_LISTS)

  add_custom_target(generated_param_header ALL DEPENDS ${GEN_PARAM_H})
  add_custom_target(generate_flatbuffers ALL DEPENDS ${GENERATED_HEADERS})
endif()
