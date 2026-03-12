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

# Merge the object files of `dependency` target with that of `target`. Both
# should be static or object libraries; otherwise this is no-op.
function(merge_archive_if_static target dependency)
  list(APPEND TYPES_HAVING_OBJECTS "STATIC_LIBRARY" "OBJECT_LIBRARY")

  get_target_property(TARGET_TYPE ${target} TYPE)
  if(NOT TARGET_TYPE IN_LIST TYPES_HAVING_OBJECTS)
    return()
  endif()

  if(NOT TARGET ${dependency})
    return()
  endif()

  get_target_property(DEP_TYPE ${dependency} TYPE)
  if(NOT DEP_TYPE IN_LIST TYPES_HAVING_OBJECTS)
    return()
  endif()

  if(TARGET_TYPE STREQUAL "OBJECT_LIBRARY" OR DEP_TYPE STREQUAL
                                              "OBJECT_LIBRARY")
    message(
      WARNING
        "merge_archive_if_static does not support OBJECT_LIBRARY with archive extraction: "
        "${target} <- ${dependency}")
    return()
  endif()

  if(MSVC)
    add_custom_command(
      TARGET ${target}
      POST_BUILD
      COMMAND lib.exe /OUT:$<TARGET_FILE:${target}> $<TARGET_FILE:${target}>
              $<TARGET_FILE:${dependency}>
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
  elseif(CMAKE_AR)
    add_custom_command(
      TARGET ${target}
      POST_BUILD
      COMMAND
        ${CMAKE_COMMAND} -DTARGET_ARCHIVE=$<TARGET_FILE:${target}>
        -DDEP_ARCHIVE=$<TARGET_FILE:${dependency}>
        -DWORK_DIR=${CMAKE_CURRENT_BINARY_DIR}/merge_${target}_${dependency}
        -DAR_TOOL=${CMAKE_AR} -P ${CMAKE_CURRENT_LIST_DIR}/merge_archives.cmake
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
  else()
    message(
      WARNING "Unsupported archiver for merging ${target} and ${dependency}")
  endif()
endfunction()
