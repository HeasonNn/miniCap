#pragma once

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#include "header.h"

#define HASH_TABLE_SIZE 100

typedef struct HashItem {
    void *key;
    void *value;
    struct HashItem *next;
} HashItem;

typedef struct HashTable {
    HashItem **items;
    int size;
    unsigned int (*hash)(void *key);         // 哈希函数指针
    int (*compare)(void *key1, void *key2);  // 键比较函数指针
    int (*insert)(struct HashTable *table, void *key, void *value);
    int (*search)(struct HashTable *table, void *key, void **value_out);
    int (*delete)(struct HashTable *table, void *key);
} HashTable;

/*
    (1) create;
    (2) insert;
    (3) remove;
    (4) update;
    (5) search;
 */

// common func
HashTable *create_table(int size, unsigned int (*hash_func)(void *key),
                        int (*compare_func)(void *key1, void *key2));
HashItem *create_item(void *key, void *value, HashItem *next);
int free_table(HashTable *hash_table);

int insert(HashTable *hash_table, void *key, void *value);
int search(HashTable *hash_table, void *key, void **value_out);
int delete(HashTable *hash_table, void *key);

// individual func
unsigned int hash_five_tuple(void *key);
int compare_five_tuple(void *key1, void *key2);
