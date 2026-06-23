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

cmake_minimum_required(VERSION 3.21)
project(
  deb
  VERSION 0.4.1
  LANGUAGES CXX
  DESCRIPTION "CryptoLab's official cryptosystem library for FHE.")

# honor visibility properties for all target types
set(CMAKE_POLICY_DEFAULT_CMP0063 NEW)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Set the C++ standards
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_VISIBILITY_INLINES_HIDDEN OFF)

set(CMAKE_INSTALL_PREFIX
    ${CMAKE_CURRENT_SOURCE_DIR}/install
    CACHE PATH "Install path prefix" FORCE)

set(DEB_MEMORY_ALIGN_SIZE
    "0"
    CACHE STRING "Memory alignment size in bytes. 0 means no alignment.")
set(DEB_EXT_LIB_FOR_SECURE_ZERO
    "NONE"
    CACHE
      STRING
      "External library for secure zeroing of memory. Options: NATIVE, LIBSODIUM, OPENSSL, NONE."
)
message(STATUS "Memory alignment size: ${DEB_MEMORY_ALIGN_SIZE} bytes")
message(
  STATUS "External library for secure zeroing: ${DEB_EXT_LIB_FOR_SECURE_ZERO}")

set(PRE_BUILD_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/prebuild)
set(PRE_BUILD_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include/generated)

file(MAKE_DIRECTORY ${PRE_BUILD_DIR})
message(STATUS "Generate pre-build directory: ${PRE_BUILD_DIR}")

include(cmake/CPM.cmake)
include(cmake/warnings.cmake)

option(BUILD_SHARED_LIBS "Build a shared library instead of a static one." OFF)
option(DEB_BUILD_BENCHMARK "Build the benchmark suite." OFF)
option(DEB_BUILD_DOXYGEN "Build the documentation with Doxygen." OFF)
option(DEB_BUILD_EXAMPLES "Build the example programs." ON)
option(DEB_BUILD_TEST "Build the test suite." ON)
option(DEB_BUILD_WITH_OMP "Build with OpenMP support." ON)
option(DEB_INSTALL "Install the deb library and headers." ON)
option(DEB_INSTALL_ALEA "Install the alea library when installing deb." OFF)
option(DEB_INSTALL_FLATBUFFERS
       "Install the flatbuffers library when installing deb." OFF)
option(DEB_RUNTIME_RESOURCE_CHECK "Enable runtime resource check." ON)
option(DEB_SERIALIZE_API "Enable serialize API." ON)
option(DEB_SUPPORT_U64 "Compile u64 coefficient word type support." ON)
option(DEB_SUPPORT_U32 "Compile u32 coefficient word type support." OFF)

if(NOT DEB_SUPPORT_U64 AND NOT DEB_SUPPORT_U32)
  message(
    FATAL_ERROR "At least one of DEB_SUPPORT_U64 or DEB_SUPPORT_U32 must be ON."
  )
elseif(NOT DEB_SUPPORT_U64)
  set(DEB_BUILD_BENCHMARK OFF)
  set(DEB_BUILD_EXAMPLES OFF)
  message(
    WARNING
      "DEB_SUPPORT_U64 is OFF, disabling benchmark suite and examples since they rely on u64 support."
  )
endif()

if(BUILD_SHARED_LIBS)
  set(DEB_INSTALL_ALEA
      ON
      CACHE BOOL
            "Enable installation of alea library for shared library build."
            FORCE)
  set(DEB_INSTALL_FLATBUFFERS
      ON
      CACHE
        BOOL
        "Enable installation of flatbuffers library for shared library build."
        FORCE)
endif()

add_subdirectory(external)
add_subdirectory(prebuild)

set(DEB_SRC
    src/AleaRandomGenerator.cpp
    src/CKKSTypes.cpp
    src/Decryptor.cpp
    src/Encryptor.cpp
    src/FFT.cpp
    src/KeyGenerator.cpp
    src/ModArith.cpp
    src/NTT.cpp
    src/NTTConfig.cpp
    src/OmpUtils.cpp
    src/Preset.cpp
    src/RandomGenerator.cpp
    src/SecretKeyGenerator.cpp
    src/SeedGenerator.cpp)

if(BUILD_SHARED_LIBS)
  add_library(${PROJECT_NAME} SHARED ${DEB_SRC})
  target_link_libraries(${PROJECT_NAME}
                        PUBLIC alea $<$<BOOL:${DEB_SERIALIZE_API}>:flatbuffers>)
else()
  add_library(
    ${PROJECT_NAME} STATIC
    ${DEB_SRC} $<TARGET_OBJECTS:alea>
    $<$<BOOL:${DEB_SERIALIZE_API}>:$<TARGET_OBJECTS:flatbuffers>>)
  target_link_libraries(
    ${PROJECT_NAME}
    PUBLIC $<BUILD_INTERFACE:alea>
           $<$<BOOL:${DEB_SERIALIZE_API}>:$<BUILD_INTERFACE:flatbuffers>>)
endif()

if(DEB_SERIALIZE_API)
  target_sources(${PROJECT_NAME} PRIVATE src/Serialize.cpp)
  add_dependencies(${PROJECT_NAME} generated_flatbuffers)
  target_compile_definitions(${PROJECT_NAME} PUBLIC DEB_SERIALIZE)
endif()
add_dependencies(${PROJECT_NAME} generated_param_header)
add_library(${PROJECT_NAME}::${PROJECT_NAME} ALIAS ${PROJECT_NAME})
set_deb_warnings(${PROJECT_NAME})
set_property(TARGET ${PROJECT_NAME} PROPERTY POSITION_INDEPENDENT_CODE ON)
target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_17)

if(NOT MSVC)
  target_compile_options(${PROJECT_NAME} PRIVATE -Wno-pedantic)
endif()

string(TOUPPER "${DEB_EXT_LIB_FOR_SECURE_ZERO}" _deb_secure_zero_backend)
if(_deb_secure_zero_backend STREQUAL "LIBSODIUM")
  target_compile_definitions(${PROJECT_NAME} PUBLIC DEB_SECURE_ZERO_LIBSODIUM)
  target_link_libraries(${PROJECT_NAME} PRIVATE sodium)
elseif(_deb_secure_zero_backend STREQUAL "OPENSSL")
  target_compile_definitions(${PROJECT_NAME} PUBLIC DEB_SECURE_ZERO_OPENSSL)
  target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::Crypto)
elseif(_deb_secure_zero_backend STREQUAL "NATIVE")
  target_compile_definitions(${PROJECT_NAME} PUBLIC DEB_SECURE_ZERO_NATIVE)
endif()
unset(_deb_secure_zero_backend)

target_include_directories(
  ${PROJECT_NAME}
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/${PROJECT_NAME}>
         $<BUILD_INTERFACE:${PRE_BUILD_DIR}>
         $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

if(DEB_RUNTIME_RESOURCE_CHECK)
  target_compile_definitions(${PROJECT_NAME} PUBLIC DEB_RESOURCE_CHECK)
endif()

if(DEB_SUPPORT_U64)
  target_compile_definitions(${PROJECT_NAME} PUBLIC DEB_U64)
endif()
if(DEB_SUPPORT_U32)
  target_compile_definitions(${PROJECT_NAME} PUBLIC DEB_U32)
endif()
target_compile_definitions(${PROJECT_NAME}
                           PUBLIC DEB_ALINAS_LEN=${DEB_MEMORY_ALIGN_SIZE})

if(DEB_BUILD_WITH_OMP)
  find_package(OpenMP REQUIRED)
  target_link_libraries(${PROJECT_NAME} PUBLIC OpenMP::OpenMP_CXX)
  target_compile_definitions(${PROJECT_NAME} PUBLIC DEB_OPENMP)
  if(MSVC)
    target_compile_options(${PROJECT_NAME} PUBLIC -openmp:llvm)
  endif()
endif()

# Build the documentation
if(DEB_BUILD_DOXYGEN)
  find_package(Doxygen)
  if(DOXYGEN_FOUND)
    set(DOXYGEN_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deb_doc)
    set(DOXYGEN_PROJECT_NAME ${DEB_PROJECT_NAME})
    set(DOXYGEN_PROJECT_NUMBER ${PROJECT_VERSION})
    set(DOXYGEN_PROJECT_BRIEF
        "CryptoLab's official cryptosystem library for FHE.")
    set(DOXYGEN_EXTRACT_ALL YES)
    set(DOXYGEN_GENERATE_LATEX NO)
    set(DOXYGEN_GENERATE_HTML YES)
    set(DOXYGEN_USE_MDFILE_AS_MAINPAGE ${CMAKE_CURRENT_SOURCE_DIR}/README.md)

    doxygen_add_docs(
      deb_doc
      ${CMAKE_CURRENT_SOURCE_DIR}/include/deb/CKKSTypes.hpp
      ${CMAKE_CURRENT_SOURCE_DIR}/include/deb/Constant.hpp
      ${CMAKE_CURRENT_SOURCE_DIR}/include/deb/Context.hpp
      ${CMAKE_CURRENT_SOURCE_DIR}/include/deb/Decryptor.hpp
      ${CMAKE_CURRENT_SOURCE_DIR}/include/deb/Encryptor.hpp
      ${CMAKE_CURRENT_SOURCE_DIR}/include/deb/KeyGenerator.hpp
      ${CMAKE_CURRENT_SOURCE_DIR}/include/deb/SecretKeyGenerator.hpp
      ${CMAKE_CURRENT_SOURCE_DIR}/include/deb/Serialize.hpp
      ${CMAKE_CURRENT_SOURCE_DIR}/include/deb/Types.hpp
      ${CMAKE_CURRENT_SOURCE_DIR}/README.md
      ALL
      COMMENT "Generate documentation with Doxygen")
  else()
    message(STATUS "Doxygen not found, documentation will not be generated.")
  endif()
endif()

if(DEB_BUILD_BENCHMARK)
  add_subdirectory(benchmark)
endif()

if(DEB_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

if(DEB_BUILD_TEST)
  enable_testing()
  add_subdirectory(test)
endif()

if(APPLE)
  set_target_properties(${PROJECT_NAME} PROPERTIES INSTALL_RPATH "@loader_path"
                                                   BUILD_RPATH "@loader_path")
else()
  set_target_properties(${PROJECT_NAME} PROPERTIES INSTALL_RPATH "$ORIGIN"
                                                   BUILD_RPATH "$ORIGIN")
endif()

# Install the library
if(DEB_INSTALL)
  include(GNUInstallDirs)
  install(
    TARGETS ${PROJECT_NAME}
    EXPORT ${PROJECT_NAME}Targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

  # Install header files
  install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
          DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

  # Export target for use with find_package
  install(
    EXPORT ${PROJECT_NAME}Targets
    FILE ${PROJECT_NAME}Targets.cmake
    NAMESPACE ${PROJECT_NAME}::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})

  include(CMakePackageConfigHelpers)

  configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/${PROJECT_NAME}Config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})

  write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion)

  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
                ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
          DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})

  install(FILES ${alea_SOURCE_DIR}/LICENSE ${flatbuffers_SOURCE_DIR}/LICENSE
          DESTINATION ${CMAKE_INSTALL_DATADIR}/${PROJECT_NAME}/licenses)
endif()
