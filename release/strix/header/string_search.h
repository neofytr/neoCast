#ifndef B9E1623A_048D_4A91_B58A_7134761C791E
#define B9E1623A_048D_4A91_B58A_7134761C791E

#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "strix_errno.h"

#define MAX_POSITIONS 1024
typedef struct
{
    size_t *pos;
    int64_t len;
} position_t;

int64_t kmp_search(const char *pattern, const char *string, size_t pattern_len, size_t string_len);
position_t *kmp_search_all(const char *pattern, const char *string, size_t pattern_len, size_t string_len);
int64_t kmp_search_all_len(const char *pattern, const char *string, size_t pattern_len, size_t string_len);


#endif /* B9E1623A_048D_4A91_B58A_7134761C791E */
