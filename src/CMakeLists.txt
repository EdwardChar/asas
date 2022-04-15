add_library(detours STATIC
  "${CMAKE_CURRENT_SOURCE_DIR}/3rd/Detours/src/creatwth.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/3rd/Detours/src/detours.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/3rd/Detours/src/disasm.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/3rd/Detours/src/disolarm.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/3rd/Detours/src/disolarm64.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/3rd/Detours/src/disolia64.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/3rd/Detours/src/disolx64.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/3rd/Detours/src/disolx86.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/3rd/Detours/src/image.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/3rd/Detours/src/modules.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/3rd/Detours/src/uimports.cpp"
)
set_property(SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/3rd/Detours/src/uimports.cpp" APPEND PROPERTY HEADER_FILE_ONLY true)
target_compile_definitions(detours PRIVATE
  WIN32_LEAN_AND_MEAN
  _WIN32_WINNT=0x0600
  DETOURS_VERSION=0x4c0c1
  $<$<EQUAL:${CMAKE_SIZEOF_VOID_P},4>:_X86_>
  $<$<EQUAL:${CMAKE_SIZEOF_VOID_P},4>:DETOURS_TARGET_PROCESSOR=X86>
  $<$<EQUAL:${CMAKE_SIZEOF_VOID_P},8>:_AMD64_>
  $<$<EQUAL:${CMAKE_SIZEOF_VOID_P},8>:DETOURS_TARGET_PROCESSOR=X64>
)
target_compile_options(detours PRIVATE
  -ffunction-sections
  -fdata-sections
  -flto
  -fno-exceptions
  -stdlib=libc++
  -rtlib=compiler-rt
)

add_custom_target(generate_version_h COMMAND
  ${CMAKE_COMMAND}
  -Dlocal_dir="${PROJECT_SOURCE_DIR}"
  -Dinput_file="${CMAKE_CURRENT_SOURCE_DIR}/version.h.in"
  -Doutput_file="${CMAKE_CURRENT_BINARY_DIR}/version.h"
  -Dnewline="LF"
  -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.cmake"
)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(ASAS_BITSIZE 64)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
  set(ASAS_BITSIZE 32)
endif()

add_library(asas_dll SHARED
  dllmain.c
  dllmain.def
)
set_target_properties(asas_dll PROPERTIES
  OUTPUT_NAME "asas${ASAS_BITSIZE}.dll"
  PREFIX ""
  SUFFIX ""
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
target_include_directories(asas_dll PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/3rd/Detours/src/" # for detours.h
)
target_link_libraries(asas_dll PRIVATE
  detours
)
add_dependencies(asas_dll detours generate_version_h)
list(APPEND targets asas_dll)

if(CMAKE_SIZEOF_VOID_P EQUAL 4)
  add_custom_target(generate_readme COMMAND
    ${CMAKE_COMMAND}
    -Dlocal_dir="${PROJECT_SOURCE_DIR}"
    -Dinput_file="${PROJECT_SOURCE_DIR}/README.md"
    -Doutput_file="${CMAKE_BINARY_DIR}/bin/asas.txt"
    -Dnewline="CRLF"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.cmake"
  )
  add_executable(asas_exe
    exemain.c
  )
  set_target_properties(asas_exe PROPERTIES
    OUTPUT_NAME "asas"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
  )
  target_link_options(asas_exe PRIVATE
    -municode
  )
  add_dependencies(asas_exe generate_version_h generate_readme)
  list(APPEND targets asas_exe)
endif()

foreach(target ${targets})
  target_include_directories(${target} PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR} # for version.h
  )
  target_compile_definitions(${target} PRIVATE
    _WIN32_WINNT=0x0600
    _WINDOWS
    WIN32_LEAN_AND_MEAN
    $<$<CONFIG:Release>:NDEBUG>
  )
  target_compile_options(${target} PRIVATE
    -Wall
    -Wextra
    -Werror
    -Weverything
    -Wshadow
    -Werror=return-type
    -pedantic-errors
    -Wno-declaration-after-statement
    -ffunction-sections
    -fdata-sections
    $<$<CONFIG:Debug>:-O0>
    $<$<CONFIG:Release>:-O3>
    -flto
    -rtlib=compiler-rt
  )
  target_link_options(${target} PRIVATE
    -rtlib=compiler-rt
    -unwindlib=libunwind
    -fuse-ld=lld
    -Wl,--gc-sections
    # -Wl,--print-gc-sections
    -static
    $<$<CONFIG:Release>:-s>
    -Wl,--kill-at
  )
endforeach(target)
