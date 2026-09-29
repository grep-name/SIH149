cmake_minimum_required(VERSION 3.12)
project(forge C)

# FORGE - Integrated Secure Data Erasure & Forensic Recovery Platform
# SIH 2025 problem statement 26149 (NTRO)
#
# Builds with MinGW-w64/gcc on Windows, gcc on Linux and clang on macOS.
# No third-party dependencies: crypto, JSON and the HTTP server are all in-tree.

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  add_compile_options(-Wall -Wextra -Wshadow -Wno-unused-parameter)
  set(CMAKE_C_FLAGS_RELEASE "-O2")
  set(CMAKE_C_FLAGS_DEBUG   "-O0 -g")
elseif(MSVC)
  add_compile_options(/W3 /D_CRT_SECURE_NO_WARNINGS)
endif()


add_executable(bin2c tools/bin2c.c)

set(UI_SRC  ${CMAKE_CURRENT_SOURCE_DIR}/ui/dashboard.html)
set(UI_GEN  ${CMAKE_CURRENT_BINARY_DIR}/generated/ui_dashboard.c)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/generated)
add_custom_command(
  OUTPUT  ${UI_GEN}
  COMMAND bin2c ${UI_SRC} ${UI_GEN} fg_ui_dashboard_html
  DEPENDS bin2c ${UI_SRC}
  COMMENT "Embedding the dashboard into the binary")


set(FG_SOURCES
  src/core/util.c
  src/core/sha256.c
  src/core/rng.c
  src/core/json.c
  src/platform/posix.c
  src/platform/win32.c
  src/erase/patterns.c
  src/erase/drive.c
  src/erase/file.c
  src/carve/signatures.c
  src/carve/aho.c
  src/carve/classify.c
  src/carve/carver.c
  src/fs/parts.c
  src/fs/emit.c
  src/fs/ntfs.c
  src/fs/fat.c
  src/fs/ext.c
  src/report/audit.c
  src/report/report.c
  src/ui/jobs.c
  src/ui/httpd.c
)

add_library(forge_core STATIC ${FG_SOURCES} ${UI_GEN})

target_include_directories(forge_core
  PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/fs)

add_executable(forge src/cli/main.c)
target_link_libraries(forge PRIVATE forge_core)


if(WIN32)
  target_link_libraries(forge_core PUBLIC ws2_32 bcrypt setupapi)
  target_compile_definitions(forge_core PUBLIC _WIN32_WINNT=0x0601 WINVER=0x0601)
else()
  find_package(Threads REQUIRED)
  target_link_libraries(forge_core PUBLIC Threads::Threads)
endif()


enable_testing()
add_executable(forge_mkimage tests/mkimage.c)
target_link_libraries(forge_mkimage PRIVATE forge_core)

add_executable(forge_score tests/score.c)
target_link_libraries(forge_score PRIVATE forge_core)

add_test(NAME selftest COMMAND forge selftest)


add_test(NAME build_image
         COMMAND forge_mkimage ${CMAKE_CURRENT_BINARY_DIR}/case.img 64)

add_test(NAME clean_audit
         COMMAND ${CMAKE_COMMAND} -E rm -f ${CMAKE_CURRENT_BINARY_DIR}/test-audit.log)

add_test(NAME recover_image
         COMMAND forge recover --source ${CMAKE_CURRENT_BINARY_DIR}/case.img
                 --out ${CMAKE_CURRENT_BINARY_DIR}/recovered
                 --report ${CMAKE_CURRENT_BINARY_DIR}/recovery.json
                 --audit-log ${CMAKE_CURRENT_BINARY_DIR}/test-audit.log --quiet)

add_test(NAME score_recovery
         COMMAND forge_score ${CMAKE_CURRENT_BINARY_DIR}/case.img.manifest.csv
                 ${CMAKE_CURRENT_BINARY_DIR}/recovery.json)

add_test(NAME verify_audit
         COMMAND forge audit verify --log ${CMAKE_CURRENT_BINARY_DIR}/test-audit.log)

set_tests_properties(recover_image PROPERTIES DEPENDS "build_image;clean_audit")
set_tests_properties(score_recovery PROPERTIES DEPENDS recover_image)
set_tests_properties(verify_audit   PROPERTIES DEPENDS recover_image)

install(TARGETS forge RUNTIME DESTINATION bin)
install(DIRECTORY docs/ DESTINATION share/doc/forge)
