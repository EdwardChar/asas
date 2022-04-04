# Based on
# https://bravenewmethod.com/2017/07/14/git-revision-as-compiler-definition-in-build-with-cmake/
# https://github.com/tikonen/blog/tree/master/cmake/git_version
cmake_minimum_required(VERSION 3.0.0)

find_package(Git REQUIRED)
execute_process(
  COMMAND ${GIT_EXECUTABLE} tag --points-at HEAD
  WORKING_DIRECTORY "${local_dir}"
  OUTPUT_VARIABLE git_tag
  ERROR_QUIET
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
if ("${git_tag}" STREQUAL "")
  set(git_tag "vX.X.X")
endif()
message(STATUS "git tag: ${git_tag}")

execute_process(
  COMMAND ${GIT_EXECUTABLE} rev-parse --short HEAD
  WORKING_DIRECTORY "${local_dir}"
  OUTPUT_VARIABLE git_revision
  ERROR_QUIET
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
if ("${git_revision}" STREQUAL "")
  set(git_revision "unknown")
endif()
message(STATUS "git revision: ${git_revision}")

if("${newline}" STREQUAL "")
  set(newline "CRLF")
endif()

configure_file(${input_file} ${output_file} @ONLY NEWLINE_STYLE ${newline})
