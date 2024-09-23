cmake_minimum_required(VERSION 3.10)
project(miniCap)

set(CMAKE_C_STANDARD 17)

add_subdirectory(src/lib)
add_subdirectory(src/parse)

add_executable(miniCap src/main.c)

target_link_libraries(miniCap PRIVATE mylib parse pcap event pthread)