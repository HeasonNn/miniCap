cmake_minimum_required(VERSION 3.10)

project(miniCap VERSION 1.0)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)

include_directories(
    src/include 
    src/include/parse
)

file(GLOB LIB_SOURCES "src/lib/*.c")
file(GLOB PARSE_SOURCES "src/lib/parse/*.c")

add_library(mylib STATIC ${LIB_SOURCES})
add_library(parse STATIC ${PARSE_SOURCES})

add_executable(miniCap src/main.c)

target_link_libraries(parse mylib)
target_link_libraries(miniCap
    mylib
    parse
    event 
    pthread 
    pcap 
    hiredis
)

add_subdirectory(tests)