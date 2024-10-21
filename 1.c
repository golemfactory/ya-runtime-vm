#include <stdio.h>
#include <stdint.h>

static uint64_t get_next_id(void)
{
    static uint64_t id = 0;
    return ++id;
}

int main() { printf("%d\n", get_next_id()); }
