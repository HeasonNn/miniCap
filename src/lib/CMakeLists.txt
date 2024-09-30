# 创建库
add_library(mylib STATIC
    format_utils.c
    write.c
    hash_table.c
)

# 设置包含目录
target_include_directories(mylib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})