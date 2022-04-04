cmake_minimum_required(VERSION 3.13)
project(asas LANGUAGES C CXX)
enable_testing()

find_program(CLANG_FORMAT_EXE clang-format)
file(GLOB sources "${PROJECT_SOURCE_DIR}/src/*.c")
add_custom_target(${PROJECT_NAME}-format ALL
  COMMAND ${CLANG_FORMAT_EXE} -style=file -i ${sources}
)

add_subdirectory(src)
