#include "../header/strix_errno.h"

void strix_perror(const char *prefix)
{
    if (prefix && *prefix)
    {
        fprintf(stderr, "%s: %s\n", prefix, strix_error_messages[strix_errno]);
    }
    else
    {
        fprintf(stderr, "%s\n", strix_error_messages[strix_errno]);
    }
}

strix_error_t strix_get_error(void)
{
    return strix_errno;
}