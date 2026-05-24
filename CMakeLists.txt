cmake_minimum_required(VERSION 4.2.0)
project(killall LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(killall killall.cpp)

if(MSVC)
    target_compile_options(killall PRIVATE /W4)
    # Prefer static embedding of VCRuntime for portability to older Windows
    set_target_properties(killall PROPERTIES
        MSVC_RUNTIME_LIBRARY "$<IF:$<CONFIG:Debug>,MultiThreadedDebugDLL,MultiThreaded>"
    )
endif()
