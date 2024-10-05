#include "redis.h"

// 初始化 Redis 客户端
RedisClient *redis_init(const char *hostname, int port)
{
    RedisClient *client = (RedisClient *)malloc(sizeof(RedisClient));
    if (client == NULL)
    {
        fprintf(stderr, "Failed to allocate memory for RedisClient\n");
        return NULL;
    }

    client->context = redisConnect(hostname, port);
    if (client->context == NULL || client->context->err)
    {
        if (client->context)
        {
            fprintf(stderr, "Redis connection error: %s\n",
                    client->context->errstr);
            redisFree(client->context);
        }
        else
        {
            fprintf(stderr, "Can't allocate Redis context\n");
        }
        free(client);
        return NULL;
    }

    printf("Connected to Redis at %s:%d\n", hostname, port);
    return client;
}

// 执行 Redis 命令
redisReply *redis_execute_command(RedisClient *client, const char *format, ...)
{
    if (client == NULL || client->context == NULL)
    {
        fprintf(stderr, "Invalid Redis client or context\n");
        return NULL;
    }

    va_list args;
    va_start(args, format);
    redisReply *reply =
        (redisReply *)redisvCommand(client->context, format, args);
    va_end(args);

    if (reply == NULL)
    {
        fprintf(stderr, "Redis command execution error: %s\n",
                client->context->errstr);
        return NULL;
    }

    return reply;
}

// 释放 Redis 回复对象
void redis_free_reply(redisReply *reply)
{
    if (reply != NULL)
    {
        freeReplyObject(reply);
    }
}

// 关闭 Redis 客户端
void redis_close(RedisClient *client)
{
    if (client != NULL)
    {
        if (client->context != NULL)
        {
            redisFree(client->context);
        }
        free(client);
    }
}

// 设置数据
int redis_set(RedisClient *client, const char *key, const char *value)
{
    redisReply *reply = redis_execute_command(client, "SET %s %s", key, value);
    if (reply == NULL)
    {
        return -1;  // 错误
    }
    int success =
        (reply->type == REDIS_REPLY_STATUS && strcmp(reply->str, "OK") == 0);
    redis_free_reply(reply);
    return success ? 0 : -1;
}

// 获取数据
char *redis_get(RedisClient *client, const char *key)
{
    redisReply *reply = redis_execute_command(client, "GET %s", key);
    if (reply == NULL)
    {
        return NULL;  // 错误
    }

    char *value = NULL;
    if (reply->type == REDIS_REPLY_STRING)
    {
        value = strdup(reply->str);  // 复制字符串以返回
    }
    redis_free_reply(reply);
    return value;  // 返回值，调用者需要负责释放内存
}

// 删除数据
int redis_delete(RedisClient *client, const char *key)
{
    redisReply *reply = redis_execute_command(client, "DEL %s", key);
    if (reply == NULL)
    {
        return -1;  // 错误
    }

    int deleted_count = reply->integer;  // 回复的整数表示删除的键数量
    redis_free_reply(reply);
    return deleted_count > 0
               ? 0
               : -1;  // 返回 0 表示成功删除，-1 表示没有删除任何键
}