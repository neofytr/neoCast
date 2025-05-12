#include "../header/string_search.h"

int64_t kmp_search(const char *pattern, const char *string, size_t pattern_len, size_t string_len)
{
    size_t lps[pattern_len];

    size_t i = 1, j = 0;
    lps[0] = 0;

    while (i < pattern_len)
    {
        if (pattern[i] == pattern[j])
        {
            j++;
            lps[i] = j;
            i++;
        }
        else
        {
            if (j != 0)
            {
                j = lps[j - 1];
            }
            else
            {
                lps[i] = 0;
                i++;
            }
        }
    }

    i = 0;
    j = 0;

    while (i < string_len)
    {
        if (pattern[j] == string[i])
        {
            j++;
            i++;

            if (j == pattern_len)
            {
                j = lps[j - 1]; // the search can be continued using this, but i return after finding the first match
                return (i - j - 1);
            }
        }
        else
        {
            if (j > 0)
            {
                j = lps[j - 1];
            }
            else
            {
                i++;
            }
        }
    }

    return -2;
}

int64_t kmp_search_all_len(const char *pattern, const char *string, size_t pattern_len, size_t string_len)
{
    size_t lps[pattern_len];
    int64_t counter = 0;

    size_t i = 1, j = 0;
    lps[0] = 0;

    while (i < pattern_len)
    {
        if (pattern[i] == pattern[j])
        {
            j++;
            lps[i] = j;
            i++;
        }
        else
        {
            if (j != 0)
            {
                j = lps[j - 1];
            }
            else
            {
                lps[i] = 0;
                i++;
            }
        }
    }

    i = 0;
    j = 0;

    while (i < string_len)
    {
        if (pattern[j] == string[i])
        {
            j++;
            i++;

            if (j == pattern_len)
            {
                j = lps[j - 1];
                counter++;
            }
        }
        else
        {
            if (j > 0)
            {
                j = lps[j - 1];
            }
            else
            {
                i++;
            }
        }
    }

    return counter;
}

position_t *kmp_search_all(const char *pattern, const char *string, size_t pattern_len, size_t string_len)
{
    if (!pattern || !string || pattern_len == 0 || pattern_len > string_len)
    {
        strix_errno = STRIX_ERR_NULL_PTR;
        return NULL;
    }

    position_t *position = (position_t *)malloc(sizeof(position_t));
    if (!position)
    {
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        return NULL;
    }
    position->pos = NULL;
    position->len = 0;

    size_t *lps = (size_t *)malloc(sizeof(size_t) * pattern_len);
    if (!lps)
    {
        free(position);
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        return NULL;
    }

    size_t current_max_positions = (string_len / pattern_len) + 1;
    if (current_max_positions > MAX_POSITIONS)
    {
        current_max_positions = MAX_POSITIONS;
    }

    size_t *pos_arr = (size_t *)malloc(sizeof(size_t) * current_max_positions);
    if (!pos_arr)
    {
        free(lps);
        free(position);
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        return NULL;
    }

    size_t i = 1, j = 0;
    lps[0] = 0;
    while (i < pattern_len)
    {
        if (pattern[i] == pattern[j])
        {
            j++;
            lps[i] = j;
            i++;
        }
        else
        {
            if (j != 0)
            {
                j = lps[j - 1];
            }
            else
            {
                lps[i] = 0;
                i++;
            }
        }
    }

    i = 0;
    j = 0;
    int64_t counter = 0;

    while (i < string_len)
    {
        if (pattern[j] == string[i])
        {
            j++;
            i++;
            if (j == pattern_len)
            {
                if (counter >= current_max_positions)
                {
                    size_t new_size = current_max_positions * 2;
                    if (new_size < current_max_positions)
                    {
                        new_size = SIZE_MAX / sizeof(size_t);
                    }

                    size_t *new_pos_arr = (size_t *)realloc(pos_arr, sizeof(size_t) * new_size);
                    if (!new_pos_arr)
                    {
                        free(pos_arr);
                        free(lps);
                        free(position);
                        strix_errno = STRIX_ERR_MALLOC_FAILED;
                        return NULL;
                    }
                    pos_arr = new_pos_arr;
                    current_max_positions = new_size;
                }

                pos_arr[counter++] = i - pattern_len;
                j = lps[j - 1];
            }
        }
        else
        {
            if (j > 0)
            {
                j = lps[j - 1];
            }
            else
            {
                i++;
            }
        }
    }

    free(lps);

    if (counter == 0)
    {
        free(pos_arr);
        position->len = -2;
        position->pos = NULL;
        return position;
    }

    if (counter < current_max_positions)
    {
        size_t *new_pos_arr = (size_t *)realloc(pos_arr, sizeof(size_t) * counter);
        if (new_pos_arr)
        {
            pos_arr = new_pos_arr;
        }
    }

    position->len = counter;
    position->pos = pos_arr;
    return position;
}