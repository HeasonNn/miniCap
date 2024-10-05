#include "hash_table.h"

int insert(HashTable *hash_table, void *key, void *value)
{
    unsigned int idx = hash_table->hash(key);
    HashItem *new_item = create_item(key, value, NULL);

    if (new_item == NULL)
    {
        return -1;
    }

    if (hash_table->items[idx] == NULL)
    {
        hash_table->items[idx] = new_item;
    }
    else
    {
        HashItem *current_item = hash_table->items[idx];
        while (current_item->next != NULL)
        {
            current_item = current_item->next;
        }
        current_item->next = new_item;
    }

    return 0;
}

int search(HashTable *hash_table, void *key, void **value_out)
{
    unsigned int index = hash_table->hash(key);
    HashItem *item = hash_table->items[index];

    while (item != NULL)
    {
        if (hash_table->compare(item->key, key) == 0)
        {
            *value_out = item->value;  // 返回找到的值
            return 0;                  // 成功
        }
        item = item->next;
    }

    return -1;  // 未找到
}

int delete(HashTable *hash_table, void *key)
{
    unsigned int idx = hash_table->hash(key);
    HashItem *item = hash_table->items[idx];
    HashItem *prev = NULL;

    while (item != NULL && hash_table->compare(key, item->key) != 0)
    {
        prev = item;
        item = item->next;
    }

    if (item == NULL) return -1;

    if (prev == NULL)
    {
        hash_table->items[idx] = item->next;
    }
    else
    {
        prev->next = item->next;
    }

    // free(item->key);
    // free(item->value);
    free(item);

    return 0;
}

HashTable *create_table(int size, unsigned int (*hash_func)(void *key),
                        int (*compare_func)(void *key1, void *key2))
{
    HashTable *hash_table = (HashTable *)(malloc(sizeof(HashTable)));

    hash_table->size = size;
    hash_table->items = (HashItem **)(calloc(size, sizeof(HashItem)));

    hash_table->hash = hash_func;
    hash_table->compare = compare_func;
    hash_table->insert = insert;
    hash_table->search = search;
    hash_table->delete = delete;
}

HashItem *create_item(void *key, void *value, HashItem *next)
{
    HashItem *item = (HashItem *)(malloc(sizeof(HashItem)));
    item->key = key;
    item->value = value;
    item->next = NULL;

    return item;
}

int free_table(HashTable *table)
{
    if (table == NULL)
    {
        return -1;  // 错误处理：空指针
    }

    for (int i = 0; i < table->size; i++)
    {
        HashItem *item = table->items[i];
        while (item != NULL)
        {
            HashItem *temp = item;
            item = item->next;
            free(temp->key);
            free(temp->value);
            free(temp);
        }
    }

    free(table->items);
    free(table);
    return 0;
}

unsigned int hash_five_tuple(void *key)
{
    FiveTuple *tuple = (FiveTuple *)key;
    unsigned long int hash_value = 0;
    int i;

    if (!tuple->is_ipv6)
    {
        for (i = 12; i < 16; i++)
        {
            hash_value = (hash_value << 5) + tuple->src_ip.s6_addr[i];
            hash_value = (hash_value << 5) + tuple->dst_ip.s6_addr[i];
        }
    }
    else
    {
        for (i = 0; i < 16; i++)
        {
            hash_value = (hash_value << 5) + tuple->src_ip.s6_addr[i];
            hash_value = (hash_value << 5) + tuple->dst_ip.s6_addr[i];
        }
    }

    hash_value = (hash_value << 5) + tuple->src_port;
    hash_value = (hash_value << 5) + tuple->dst_port;
    hash_value = (hash_value << 5) + tuple->protocol;

    return hash_value % HASH_TABLE_SIZE;
}

int compare_five_tuple(void *key1, void *key2)
{
    FiveTuple *a = (FiveTuple *)key1;
    FiveTuple *b = (FiveTuple *)key2;

    if (a->is_ipv6 != b->is_ipv6)
    {
        return 1;
    }

    if (a->is_ipv6)
    {
        if (memcmp(&a->src_ip, &b->src_ip, sizeof(struct in6_addr)) != 0 ||
            memcmp(&a->dst_ip, &b->dst_ip, sizeof(struct in6_addr)) != 0)
        {
            return 1;
        }
    }
    else
    {
        if (memcmp(&a->src_ip.s6_addr[12], &b->src_ip.s6_addr[12], 4) != 0 ||
            memcmp(&a->dst_ip.s6_addr[12], &b->dst_ip.s6_addr[12], 4) != 0)
        {
            return 1;
        }
    }

    return a->src_port != b->src_port || a->dst_port != b->dst_port ||
           a->protocol != b->protocol;
}