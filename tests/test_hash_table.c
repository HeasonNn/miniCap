#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hash_table.h"

void test_insert_and_search()
{
    HashTable *table = create_table(10, hash_five_tuple, compare_five_tuple);

    FiveTuple *key1 = (FiveTuple *)malloc(sizeof(FiveTuple));
    inet_pton(AF_INET, "192.168.1.1", &key1->src_ip);
    inet_pton(AF_INET, "192.168.1.2", &key1->dst_ip);
    key1->src_port = 12345;
    key1->dst_port = 80;
    key1->protocol = 6;
    key1->is_ipv6 = 0;

    // 插入键值对
    int result = table->insert(table, key1, "Test Value 1");
    if (result != 0)
    {
        printf("测试失败：插入失败\n");
        return;
    }

    // 查找键值对
    void *value = NULL;
    result = table->search(table, key1, &value);
    if (result == 0 && strcmp((char *)value, "Test Value 1") == 0)
    {
        printf("测试通过：插入和查找功能正常\n");
    }
    else
    {
        printf("测试失败：查找失败\n");
    }

    free_table(table);
}

void test_delete()
{
    HashTable *table = create_table(10, hash_five_tuple, compare_five_tuple);

    FiveTuple *key1 = (FiveTuple *)malloc(sizeof(FiveTuple));
    inet_pton(AF_INET, "192.168.1.1", &key1->src_ip);
    inet_pton(AF_INET, "192.168.1.2", &key1->dst_ip);
    key1->src_port = 12345;
    key1->dst_port = 80;
    key1->protocol = 6;
    key1->is_ipv6 = 0;

    table->insert(table, key1, "Test Value 1");

    // 删除键值对
    int result = table->delete (table, key1);
    if (result == 0)
    {
        printf("测试通过：删除功能正常\n");
    }
    else
    {
        printf("测试失败：删除失败\n");
    }

    free_table(table);
}

void test_free_table()
{
    HashTable *table = create_table(10, hash_five_tuple, compare_five_tuple);

    FiveTuple *key1 = (FiveTuple *)malloc(sizeof(FiveTuple));
    inet_pton(AF_INET, "192.168.1.1", &key1->src_ip);
    inet_pton(AF_INET, "192.168.1.2", &key1->dst_ip);
    key1->src_port = 12345;
    key1->dst_port = 80;
    key1->protocol = 6;
    key1->is_ipv6 = 0;

    table->insert(table, key1, "Test Value 1");

    int result = free_table(table);
    if (result == 0)
    {
        printf("测试通过: free_table 功能正常\n");
    }
    else
    {
        printf("测试失败: free_table 返回错误\n");
    }
}

int main()
{
    test_insert_and_search();
    test_delete();
    test_free_table();
    return 0;
}