cmake_minimum_required(VERSION 3.20)
project(killall LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Version — single source of truth
set(KILLALL_VERSION_MAJOR 1)
set(KILLALL_VERSION_MINOR 0)
set(KILLALL_VERSION_PATCH 1)
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
endif()
