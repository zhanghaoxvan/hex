cmake_minimum_required(VERSION 3.20)
project(hex LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# set(BUILD "debug")

if(NOT BUILD)
    set(BUILD "release")
endif()
if(BUILD STREQUAL "debug")
    add_compile_options(-g -O0 -Wall -Wextra)
elseif(BUILD STREQUAL "release")
    add_compile_options(-O3 -march=native -Wall -Wextra)
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
