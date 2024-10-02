# 查找 hiredis 库
find_package(PkgConfig REQUIRED)
pkg_check_modules(HIREDIS REQUIRED hiredis)

# 设置包含目录
include_directories(${HIREDIS_INCLUDE_DIRS})

# 创建库并添加源文件
add_library(mylib STATIC
    format_utils.c
    write.c
    hash_table.c
    redis.c  # 新增 redis.c
)

# 设置包含目录
target_include_directories(mylib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# 链接 hiredis 库
target_link_libraries(mylib ${HIREDIS_LIBRARIES})