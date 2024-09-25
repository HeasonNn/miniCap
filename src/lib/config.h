#include <stdio.h>

struct config_t {
    int verbose;
};

static struct config_t config = {
    .verbose = 1,
};

void read_config(struct config_t *config);