#pragma once

#include <hiredis/hiredis.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    redisContext *context;
} RedisClient;

RedisClient *redis_init(const char *hostname, int port);
redisReply *redis_execute_command(RedisClient *client, const char *format, ...);
void redis_free_reply(redisReply *reply);
void redis_close(RedisClient *client);

int redis_set(RedisClient *client, const char *key, const char *value);
char *redis_get(RedisClient *client, const char *key);
int redis_delete(RedisClient *client, const char *key);