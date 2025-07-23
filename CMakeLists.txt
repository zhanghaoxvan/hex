cmake_minimum_required(VERSION 3.20)
project(hex LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(./cmake-module/message.cmake)

# set(CMAKE_BUILD_TYPE Debug)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-g -O0 -Wall -Wextra)
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-O3 -march=native -Wall -Wextra)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")  # GCC or Clang
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        print_options(GNU/Clang Debug)
        add_compile_options(-std=c++20 -g -O0 -Wall -Wextra)
    else()
        print_options(GNU/Clang Release)
        add_compile_options(-std=c++20 -O3 -march=native -Wall -Wextra)
    endif()
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")  # MSVC (Visual Studio)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        print_options(MSVC Debug)
        add_compile_options(/Zi /Od /W4)
    else()
        print_options(MSVC Release)
        add_compile_options(/O2 /W4)
    endif()
    
    add_compile_options(/wd4251 /wd4275)
endif()

set(FTXUI_DIR "./FTXUI")
if(NOT EXISTS ${FTXUI_DIR})
    set(FTXUI_DIR ${CMAKE_SOURCE_DIR}/FTXUI)
endif()

set(NCURSES_DIR "${CMAKE_SOURCE_DIR}/ncurses")
include_directories(${NCURSES_DIR}/include)
link_directories(${NCURSES_DIR}/lib)

file(GLOB_RECURSE SRCS "src/*.cpp")
include_directories(include)
include_directories(${FTXUI_DIR}/include)

add_subdirectory(${FTXUI_DIR})

add_executable(hex ${SRCS})

target_link_libraries(hex
    PRIVATE
    ftxui::component
    ftxui::dom
    ftxui::screen
    pthread
)

if(WIN32)
    target_link_libraries(hex PRIVATE ncursesw)
elseif(UNIX)
    target_link_libraries(hex PRIVATE ncursesw)
endif()

if(WIN32)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static -static-libgcc -static-libstdc++")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
    if(MINGW)
        target_link_libraries(hex PRIVATE -static-libgcc -static-libstdc++)
        target_link_libraries(hex PRIVATE -lws2_32 -lwinmm -ladvapi32)
    endif()
endif()

if(UNIX AND NOT APPLE)
    set(CMAKE_INSTALL_RPATH "$ORIGIN")
    set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
endif()
