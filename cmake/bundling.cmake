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
  # Check if the target has object files
  list(APPEND TYPES_HAVING_OBJECTS "STATIC_LIBRARY" "OBJECT_LIBRARY")
  get_target_property(IS_STATIC ${target} TYPE)
  if(NOT IS_STATIC IN_LIST TYPES_HAVING_OBJECTS)
    return()
  endif()

  # Check if the dependency is a target and has object files
  if(NOT TARGET ${dependency})
    return()
  endif()
  get_target_property(IS_STATIC ${dependency} TYPE)
  if(NOT IS_STATIC IN_LIST TYPES_HAVING_OBJECTS)
    return()
  endif()

  if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_custom_command(
      TARGET ${target}
      POST_BUILD
      COMMAND rm -rf ${target}_objs && mkdir ${target}_objs
      COMMAND rm -rf ${dependency}_objs && mkdir ${dependency}_objs
      COMMAND ${CMAKE_COMMAND} -E chdir ${target}_objs ${CMAKE_AR} -x
              $<TARGET_FILE:${target}>
      COMMAND ${CMAKE_COMMAND} -E chdir ${dependency}_objs ${CMAKE_AR} -x
              $<TARGET_FILE:${dependency}>
      COMMAND ar -qcs $<TARGET_FILE:${target}> ${target}_objs/*.o
              ${dependency}_objs/*.o
      COMMAND rm -rf ${target}_objs ${dependency}_objs
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}) # DEPENDS ${target}
                                                     # ${dependency})
  elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    add_custom_command(
      TARGET ${target}
      POST_BUILD
      COMMAND lib.exe /OUT:$<TARGET_FILE:${target}> $<TARGET_FILE:${target}>
              $<TARGET_FILE:${dependency}>
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}) # DEPENDS ${target}
                                                     # ${dependency})
  else()
    message(
      WARNING
        "Failed merging ${target} target with ${dependency}: unsupported compiler"
    )
  endif()
endfunction()
