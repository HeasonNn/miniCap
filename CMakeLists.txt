cmake_minimum_required(VERSION 3.10)

# 设置项目名称和版本
project(MyProject VERSION 1.0)

# 设置 C 标准
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)

# 包含头文件目录
include_directories(src/include src/include/parse)

# 添加源文件
file(GLOB_RECURSE LIB_SOURCES src/lib/*.c)
file(GLOB_RECURSE PARSE_SOURCES src/lib/parse/*.c)

# 添加可执行文件
add_executable(miniCap src/main.c ${LIB_SOURCES} ${PARSE_SOURCES})

# 链接需要的外部库
target_link_libraries(miniCap event pthread pcap hiredis)

# 添加 tests 子目录
add_subdirectory(tests)

# 可选项：添加自定义编译选项或定义
# add_compile_options(-Wall -Wextra)