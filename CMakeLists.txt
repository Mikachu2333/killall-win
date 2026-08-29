cmake_minimum_required(VERSION 4.1.0)
project(killall LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Version — single source of truth
set(KILLALL_VERSION_MAJOR 1)
set(KILLALL_VERSION_MINOR 2)
set(KILLALL_VERSION_PATCH 0)
set(KILLALL_VERSION_BUILD 0)
set(KILLALL_VERSION_STR "${KILLALL_VERSION_MAJOR}.${KILLALL_VERSION_MINOR}.${KILLALL_VERSION_PATCH}.${KILLALL_VERSION_BUILD}")
set(KILLALL_RC_FILEVERSION     "${KILLALL_VERSION_MAJOR},${KILLALL_VERSION_MINOR},${KILLALL_VERSION_PATCH},${KILLALL_VERSION_BUILD}")
set(KILLALL_RC_FILEVERSION_STR "${KILLALL_VERSION_STR}\\0")
set(KILLALL_RC_PRODUCTVERSION     "${KILLALL_RC_FILEVERSION}")
set(KILLALL_RC_PRODUCTVERSION_STR "${KILLALL_RC_FILEVERSION_STR}")

set(KILLALL_COMPANY             "Mikachu2333")
set(KILLALL_DESCRIPTION         "Windows Process Termination Tool")
set(KILLALL_INTERNAL_NAME       "killall")
set(KILLALL_COPYRIGHT           "MIT License")
set(KILLALL_ORIGINAL_FILENAME   "killall.exe")
set(KILLALL_PRODUCT_NAME        "killall")

configure_file(version.hpp.in ${CMAKE_CURRENT_BINARY_DIR}/version.hpp @ONLY)
configure_file(version.rc.in ${CMAKE_CURRENT_BINARY_DIR}/version.rc @ONLY)

add_executable(killall killall.cpp ${CMAKE_CURRENT_BINARY_DIR}/version.rc)
target_include_directories(killall PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})

if(MSVC)
    target_compile_options(killall PRIVATE /W4 /permissive- /utf-8 /sdl)
    # Prefer static embedding of VCRuntime for portability to older Windows
    set_target_properties(killall PROPERTIES
        MSVC_RUNTIME_LIBRARY "$<IF:$<CONFIG:Debug>,MultiThreadedDebugDLL,MultiThreaded>"
    )
endif()

include(CTest)
if(BUILD_TESTING)
    add_test(NAME killall_help COMMAND killall --help)
    add_test(NAME killall_version COMMAND killall --version)
    add_test(NAME killall_rejects_unknown_option COMMAND killall --definitely-invalid)
    set_tests_properties(killall_rejects_unknown_option PROPERTIES WILL_FAIL TRUE)
    add_test(NAME killall_rejects_invalid_port COMMAND killall --port 70000 --dry-run)
    set_tests_properties(killall_rejects_invalid_port PROPERTIES WILL_FAIL TRUE)

    # Numeric positional arguments are treated as PIDs. A PID above the DWORD
    # range can never exist, so this must list nothing and exit 0.
    add_test(NAME killall_pid_no_match COMMAND killall 5000000000 --dry-run)
    # Mixing numeric and non-numeric positional arguments stays an error.
    add_test(NAME killall_rejects_mixed_pid_and_pattern
             COMMAND killall 123 notepad --dry-run)
    set_tests_properties(killall_rejects_mixed_pid_and_pattern
                         PROPERTIES WILL_FAIL TRUE)

    # Unit tests for pure matching/parsing and Windows command-line logic
    add_executable(killall_pattern_tests tests/test_pattern.cpp)
    target_include_directories(killall_pattern_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    add_executable(killall_command_line_tests tests/test_command_line.cpp)
    target_include_directories(killall_command_line_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    if(MSVC)
        target_compile_options(killall_pattern_tests PRIVATE /W4 /permissive- /utf-8 /sdl)
        target_compile_options(killall_command_line_tests PRIVATE /W4 /permissive- /utf-8 /sdl)
    endif()
    add_test(NAME killall_pattern_tests COMMAND killall_pattern_tests)
    add_test(NAME killall_command_line_tests COMMAND killall_command_line_tests)
endif()
