#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "redis.h"

void test_redis_func() {
    RedisClient *client = redis_init("127.0.0.1", 6379);
    if (!client) {
        printf("ERR: redis_init\n");
        return;
    }
    // 设置数据
    if (redis_set(client, "five_tuple", "test_values") != 0) {
        redis_close(client);
        printf("ERR: redis_set\n");
        return;
    }

    // 获取数据
    char *value = redis_get(client, "five_tuple");
    if (value) {
        printf("Got value: %s\n", value);
        free(value);  // 释放返回的字符串
    } else {
        printf("ERR: redis_get\n");
    }

    // 关闭 Redis 连接
    redis_close(client);
}

int main() {
    test_redis_func();
    return 0;
}