cmake_minimum_required(VERSION 3.10)

project(pdbdump)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

find_package(fmt REQUIRED)
find_package(CURL REQUIRED)

set(SRC_FILES
	src/pdbdump.cpp)

add_executable(pdbdump ${SRC_FILES})

if(NOT MSVC)
    target_compile_options(pdbdump PUBLIC -Wall -Werror=cast-function-type -Wno-expansion-to-defined -Wunused-parameter -Wtype-limits -Wextra -Wconversion)
endif()
