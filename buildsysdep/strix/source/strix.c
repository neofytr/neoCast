#include <threads.h>
#include <stdint.h>

#include "../header/strix.h"
#include "../allocator/allocator.h"

static inline bool is_strix_null(const strix_t *strix)
{
    if (!strix)
    {
        strix_errno = STRIX_ERR_NULL_PTR;
        return true;
    }
    return false;
}

static inline bool is_str_null(const char *str)
{
    if (!str)
    {
        strix_errno = STRIX_ERR_NULL_PTR;
        return true;
    }
    return false;
}

static inline bool is_strix_str_null(const strix_t *strix)
{
    if (!strix->str)
    {
        strix_errno = STRIX_ERR_NULL_PTR;
        return true;
    }
    return false;
}

static inline bool is_strix_empty(const strix_t *strix)
{
    if (!strix->len)
    {
        strix_errno = STRIX_ERR_EMPTY_STRING;
        return true;
    }
    return false;
}

static inline bool is_strix_empty_or_null(const strix_t *strix)
{
    return is_strix_null(strix) || is_strix_empty(strix);
}

strix_t *strix_create_empty()
{
    char *str = allocate(0);
    if (!str)
    {
        return NULL;
    }

    strix_t *strix = (strix_t *)allocate(sizeof(strix_t));
    if (!strix)
    {
        return NULL;
    }

    strix->str = str;
    strix->len = 0;
    return strix;
}

char *strix_to_cstr(strix_t *strix)
{
    if (!strix)
    {
        return NULL;
    }

    char *str = malloc(sizeof(char) * (strix->len + 1)); // + 1 for null byte
    if (!str)
    {
        return NULL;
    }

    memcpy(str, strix->str, strix->len);

    str[strix->len] = 0; // append null byte
    return str;
}

strix_t *strix_create(const char *str)
{
    strix_errno = STRIX_SUCCESS;

    if (is_str_null(str))
    {
        return NULL;
    }

    strix_t *strix = (strix_t *)allocate(sizeof(strix_t));
    if (!strix)
    {
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        return NULL;
    }

    strix->len = strlen(str);
    if (!strix->len)
    {
        strix_errno = STRIX_ERR_EMPTY_STRING;
        deallocate(strix);
        return NULL;
    }

    strix->str = (char *)allocate(strix->len);
    if (!strix->str)
    {
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        deallocate(strix);
        return NULL;
    }

    if (!memmove(strix->str, str, strix->len))
    {
        strix_errno = STRIX_ERR_MEMMOVE_FAILED;
        deallocate(strix->str);
        deallocate(strix);
        return NULL;
    }

    return strix;
}

strix_t *strix_duplicate(const strix_t *strix)
{
    strix_errno = STRIX_SUCCESS;

    if (is_strix_empty_or_null(strix))
    {
        return NULL;
    }

    strix_t *duplicate = (strix_t *)allocate(sizeof(strix_t));
    if (!duplicate)
    {
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        return NULL;
    }

    duplicate->len = strix->len;
    duplicate->str = (char *)allocate(sizeof(char) * duplicate->len);
    if (!duplicate->str)
    {
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        deallocate(duplicate);
        return NULL;
    }

    if (!memcpy(duplicate->str, strix->str, strix->len))
    {
        strix_errno = STRIX_ERR_MEMCPY_FAILED;
        deallocate(duplicate->str);
        deallocate(duplicate);
        return NULL;
    }

    return duplicate;
}

bool strix_modify(strix_t *strix, const char *str)
{
    strix_errno = STRIX_SUCCESS;

    if (is_strix_null(strix) || is_str_null(str))
    {
        return false;
    }

    strix_free(strix);
    strix = strix_create(str);
    if (!strix)
    {
        return false;
    }
    return true;
}

void strix_free(strix_t *strix)
{
    if (!strix)
        return;
    if (strix->str)
        deallocate(strix->str);
    deallocate(strix);
}

bool strix_clear(strix_t *strix)
{
    strix_errno = STRIX_SUCCESS;

    if (is_strix_null(strix))
    {
        return false;
    }

    strix->len = 0;
    deallocate(strix->str);
    strix->str = NULL;
    return true;
}

bool strix_concat(strix_t *dest, const strix_t *src)
{
    strix_errno = STRIX_SUCCESS;

    if (is_strix_null(dest))
    {
        return false;
    }

    if (is_strix_null(src))
    {
        return true; // nothing to concatenate, not an error
    }

    size_t new_len = dest->len + src->len;
    char *new_str = (char *)allocate(sizeof(char) * new_len);
    if (!new_str)
    {
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        return false;
    }

    if (!memcpy(new_str, dest->str, dest->len))
    {
        strix_errno = STRIX_ERR_MEMCPY_FAILED;
        deallocate(new_str);
        return false;
    }

    if (!memcpy(new_str + dest->len, src->str, src->len))
    {
        strix_errno = STRIX_ERR_MEMCPY_FAILED;
        deallocate(new_str);
        return false;
    }

    deallocate(dest->str);
    dest->str = new_str;
    dest->len = new_len;

    return true;
}

bool strix_append(strix_t *strix, const char *str)
{
    strix_errno = STRIX_SUCCESS;

    if (is_strix_null(strix) || is_str_null(str))
    {
        return false;
    }

    size_t str_len = strlen(str);
    if (!str_len)
    {
        return true; // nothing to append, not an error
    }

    size_t new_len = strix->len + str_len;
    char *new_str = (char *)allocate(sizeof(char) * new_len);
    if (!new_str)
    {
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        return false;
    }

    if (!memcpy(new_str, strix->str, strix->len))
    {
        strix_errno = STRIX_ERR_MEMCPY_FAILED;
        deallocate(new_str);
        return false;
    }

    if (!memcpy(new_str + strix->len, str, str_len))
    {
        strix_errno = STRIX_ERR_MEMCPY_FAILED;
        deallocate(new_str);
        return false;
    }

    deallocate(strix->str);
    strix->str = new_str;
    strix->len = new_len;

    return true;
}

bool strix_insert_str(strix_t *strix, size_t pos, const char *substr)
{
    if (is_strix_null(strix) || is_str_null(substr))
    {
        strix_errno = STRIX_ERR_NULL_PTR;
        return false;
    }

    if (is_strix_str_null(strix))
    {
        strix_errno = STRIX_ERR_STRIX_STR_NULL;
        return false;
    }

    if (strix->len <= pos)
    {
        strix_errno = STRIX_ERR_INVALID_POS;
        return false;
    }

    char *new_str = (char *)allocate(sizeof(char) * (strlen(substr) + strix->len));
    if (is_str_null(new_str))
    {
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        return false;
    }

    if (!memcpy((void *)new_str, (void *)strix->str, pos))
    {
        strix_errno = STRIX_ERR_MEMMOVE_FAILED;
        return false;
    }

    if (!memcpy(((void *)(uint8_t *)new_str + pos), (void *)substr, strlen(substr)))
    {
        strix_errno = STRIX_ERR_MEMMOVE_FAILED;
        return false;
    }

    if (!memcpy(((void *)(uint8_t *)new_str + pos + strlen(substr)), (void *)strix->str, strix->len - pos - 1))
    {
        strix_errno = STRIX_ERR_MEMMOVE_FAILED;
        return false;
    }

    deallocate(strix->str);
    strix->str = new_str;
    strix->len = strix->len + strlen(substr);

    strix_errno = STRIX_SUCCESS;
    return true;
}

bool strix_insert(strix_t *strix_dest, strix_t *strix_src, size_t pos)
{
    if (is_strix_null(strix_dest) || is_strix_null(strix_src))
    {
        strix_errno = STRIX_ERR_NULL_PTR;
        return false;
    }

    if (is_strix_str_null(strix_dest) || is_strix_str_null(strix_src))
    {
        strix_errno = STRIX_ERR_STRIX_STR_NULL;
        return false;
    }

    if (strix_dest->len <= pos)
    {
        strix_errno = STRIX_ERR_INVALID_POS;
        return false;
    }

    char *substr = strix_src->str;
    size_t len = strix_src->len;

    char *new_str = (char *)allocate(sizeof(char) * (len + strix_dest->len));
    if (is_str_null(new_str))
    {
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        return false;
    }

    if (!memcpy((void *)new_str, (void *)strix_dest->str, pos))
    {
        strix_errno = STRIX_ERR_MEMMOVE_FAILED;
        return false;
    }

    if (!memcpy(((void *)(uint8_t *)new_str + pos), (void *)substr, len))
    {
        strix_errno = STRIX_ERR_MEMMOVE_FAILED;
        return false;
    }

    if (!memcpy(((void *)(uint8_t *)new_str + pos + len), (void *)strix_dest->str, strix_dest->len - pos - 1))
    {
        strix_errno = STRIX_ERR_MEMMOVE_FAILED;
        return false;
    }

    deallocate(strix_dest->str);
    strix_dest->str = new_str;
    strix_dest->len = strix_dest->len + len;

    strix_errno = STRIX_SUCCESS;
    return true;
}

bool strix_erase(strix_t *strix, size_t len, size_t pos)
{
    if (is_strix_null(strix))
    {
        strix_errno = STRIX_ERR_NULL_PTR;
        return false;
    }

    if (is_strix_str_null(strix))
    {
        strix_errno = STRIX_ERR_STRIX_STR_NULL;
        return false;
    }

    if (pos >= strix->len)
    {
        strix_errno = STRIX_ERR_INVALID_POS;
        return false;
    }

    if (pos + len > strix->len)
    {
        len = strix->len - pos - 1;
    }

    char *new_str = (char *)allocate(sizeof(char) * (strix->len - len));
    if (is_str_null(new_str))
    {
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        return false;
    }

    if (!memcpy((void *)new_str, (void *)strix->str, pos + 1))
    {
        strix_errno = STRIX_ERR_MEMCPY_FAILED;
        return false;
    }

    if (!memcpy((void *)((uint8_t *)new_str + pos + 1), (void *)((uint8_t *)strix->str) + pos + len + 1, strix->len - pos - len - 1))
    {
        strix_errno = STRIX_ERR_MEMCPY_FAILED;
        return false;
    }

    deallocate(strix->str);
    strix->str = new_str;
    strix->len -= len;

    strix_errno = STRIX_SUCCESS;
    return true;
}

char strix_at(const strix_t *strix, size_t index)
{
    if (is_strix_null(strix))
    {
        strix_errno = STRIX_ERR_NULL_PTR;
        return -1;
    }

    if (index >= strix->len)
    {
        strix_errno = STRIX_ERR_OUT_OF_BOUNDS_ACCESS;
        return -1;
    }

    strix_errno = STRIX_SUCCESS;
    return strix->str[index];
}

int strix_equal(const strix_t *strix_one, const strix_t *strix_two)
{
    if (is_strix_null(strix_one) || is_strix_null(strix_two))
    {
        strix_errno = STRIX_ERR_NULL_PTR;
        return -1;
    }

    if (is_strix_str_null(strix_one) || is_strix_str_null(strix_two))
    {
        strix_errno = STRIX_ERR_STRIX_STR_NULL;
        return -1;
    }

    if (strix_one->len != strix_two->len)
    {
        return 1;
    }

    strix_errno = STRIX_SUCCESS;

    size_t len = strix_one->len;
    if (!strncmp(strix_one->str, strix_two->str, len))
    {
        return 0;
    }

    return 1;
}

int64_t strix_find(const strix_t *strix, const char *substr)
{
    if (is_strix_null(strix) || is_str_null(substr))
    {
        strix_errno = STRIX_ERR_NULL_PTR;
        return -1;
    }

    if (is_strix_str_null(strix))
    {
        strix_errno = STRIX_ERR_STRIX_STR_NULL;
        return -1;
    }

    strix_errno = STRIX_SUCCESS;
    return kmp_search(substr, strix->str, strlen(substr), strix->len);
}

position_t *strix_find_all(const strix_t *strix, const char *substr)
{
    if (is_strix_null(strix) || is_str_null(substr))
    {
        strix_errno = STRIX_ERR_NULL_PTR;
        return NULL;
    }

    if (is_strix_str_null(strix))
    {
        strix_errno = STRIX_ERR_STRIX_STR_NULL;
        return NULL;
    }

    strix_errno = STRIX_SUCCESS;
    return kmp_search_all(substr, strix->str, strlen(substr), strix->len);
}

int64_t strix_find_subtrix(const strix_t *strix_one, const strix_t *strix_two)
{
    if (is_strix_null(strix_one) || is_strix_null(strix_two))
    {
        strix_errno = STRIX_ERR_NULL_PTR;
        return -1;
    }

    if (is_strix_str_null(strix_one) || is_strix_str_null(strix_two))
    {
        strix_errno = STRIX_ERR_STRIX_STR_NULL;
        return -1;
    }

    strix_errno = STRIX_SUCCESS;
    return kmp_search(strix_two->str, strix_one->str, strix_two->len, strix_one->len);
}

position_t *strix_find_subtrix_all(const strix_t *strix_one, const strix_t *strix_two)
{
    if (is_strix_null(strix_one) || is_strix_null(strix_two))
    {
        strix_errno = STRIX_ERR_NULL_PTR;
        return NULL;
    }

    if (is_strix_str_null(strix_one) || is_strix_str_null(strix_two))
    {
        strix_errno = STRIX_ERR_STRIX_STR_NULL;
        return NULL;
    }

    strix_errno = STRIX_SUCCESS;
    return kmp_search_all(strix_two->str, strix_one->str, strix_two->len, strix_one->len);
}

void strix_position_free(position_t *position)
{
    free(position->pos);
    free(position);
    strix_errno = STRIX_SUCCESS;
}

void strix_free_strix_arr(strix_arr_t *strix_arr)
{
    if (!strix_arr)
        return;

    for (size_t counter = 0; counter < strix_arr->len; counter++)
    {
        strix_free(strix_arr->strix_arr[counter]);
    }

    deallocate(strix_arr->strix_arr);
    deallocate(strix_arr);
}

strix_t *strix_slice(const strix_t *strix, size_t start, size_t end)
{
    if (start > end || end >= strix->len || is_strix_null(strix))
    {
        strix_errno = start > end || end >= strix->len ? STRIX_ERR_INVALID_BOUNDS : STRIX_ERR_NULL_PTR;
        return NULL;
    }

    strix_t *slice = (strix_t *)allocate(sizeof(strix_t));
    if (is_strix_null(slice))
    {
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        return NULL;
    }

    slice->len = end - start + 1;
    slice->str = (char *)allocate(sizeof(char) * slice->len);
    if (!slice->str)
    {
        deallocate(slice);
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        return NULL;
    }

    void *result = memcpy(slice->str, strix->str + start, slice->len);
    if (!result)
    {
        deallocate(slice->str);
        deallocate(slice);
        strix_errno = STRIX_ERR_MEMCPY_FAILED;
        return NULL;
    }

    strix_errno = STRIX_SUCCESS;
    return slice;
}

strix_arr_t *strix_split_by_delim(const strix_t *strix, const char delim)
{
    if (is_strix_null(strix) || is_strix_str_null(strix))
    {
        strix_errno = is_strix_null(strix) ? STRIX_ERR_NULL_PTR : STRIX_ERR_STRIX_STR_NULL;
        return NULL;
    }

    strix_arr_t *strix_arr_struct = (strix_arr_t *)allocate(sizeof(strix_arr_t));
    if (!strix_arr_struct)
    {
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        return NULL;
    }

    size_t current_max_size = MAX_SUBSTRIX_NUM;
    strix_t **strix_arr = (strix_t **)allocate(sizeof(strix_t *) * current_max_size);
    if (!strix_arr)
    {
        deallocate(strix_arr_struct);
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        return NULL;
    }

    size_t len = 0;
    size_t j = 0;

    for (size_t i = 0; i <= strix->len; i++)
    {
        if (i == strix->len || strix->str[i] == delim)
        {
            if (i != j)
            {
                if (len >= current_max_size)
                {
                    size_t new_size = current_max_size * 2;
                    strix_t **new_arr = (strix_t **)allocate(sizeof(strix_t *) * new_size);
                    if (!new_arr)
                    {
                        for (size_t k = 0; k < len; k++)
                        {
                            deallocate(strix_arr[k]->str);
                            deallocate(strix_arr[k]);
                        }
                        deallocate(strix_arr);
                        deallocate(strix_arr_struct);
                        strix_errno = STRIX_ERR_MALLOC_FAILED;
                        return NULL;
                    }

                    for (size_t k = 0; k < len; k++)
                    {
                        new_arr[k] = strix_arr[k];
                    }

                    deallocate(strix_arr);
                    strix_arr = new_arr;
                    current_max_size = new_size;
                }

                strix_t *substrix = strix_slice(strix, j, i - 1);
                if (is_strix_null(substrix))
                {
                    for (size_t k = 0; k < len; k++)
                    {
                        deallocate(strix_arr[k]->str);
                        deallocate(strix_arr[k]);
                    }
                    deallocate(strix_arr);
                    deallocate(strix_arr_struct);
                    return NULL;
                }
                strix_arr[len++] = substrix;
            }
            j = i + 1;
        }
    }

    if (len < current_max_size / 2)
    {
        strix_t **new_arr = (strix_t **)allocate(sizeof(strix_t *) * len);
        if (new_arr)
        {
            for (size_t k = 0; k < len; k++)
            {
                new_arr[k] = strix_arr[k];
            }
            deallocate(strix_arr);
            strix_arr = new_arr;
        }
    }

    strix_arr_struct->len = len;
    strix_arr_struct->strix_arr = strix_arr;
    strix_errno = STRIX_SUCCESS;
    return strix_arr_struct;
}

strix_arr_t *strix_split_by_substr(const strix_t *strix, const char *substr)
{
    if (is_strix_null(strix) || is_str_null(substr))
    {
        strix_errno = STRIX_ERR_NULL_PTR;
        return NULL;
    }
    if (is_strix_str_null(strix))
    {
        strix_errno = STRIX_ERR_STRIX_STR_NULL;
        return NULL;
    }

    position_t *position = strix_find_all(strix, substr);
    if (!position)
    {
        return NULL;
    }
    if (position->len == -1)
    {
        deallocate(position);
        return NULL;
    }

    strix_arr_t *strix_arr_struct = (strix_arr_t *)allocate(sizeof(strix_arr_t));
    if (!strix_arr_struct)
    {
        deallocate(position);
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        return NULL;
    }

    if (position->len == -2)
    {
        strix_t *copy = strix_duplicate(strix);
        if (!copy)
        {
            deallocate(position);
            deallocate(strix_arr_struct);
            return NULL;
        }
        strix_arr_struct->len = 1;
        strix_arr_struct->strix_arr = (strix_t **)allocate(sizeof(strix_t *));
        if (!strix_arr_struct->strix_arr)
        {
            deallocate(position);
            deallocate(copy);
            deallocate(strix_arr_struct);
            strix_errno = STRIX_ERR_MALLOC_FAILED;
            return NULL;
        }
        strix_arr_struct->strix_arr[0] = copy;
        deallocate(position);
        return strix_arr_struct;
    }

    strix_arr_struct->strix_arr = (strix_t **)allocate(sizeof(strix_t *) * MAX_SUBSTRIX_NUM);
    if (!strix_arr_struct->strix_arr)
    {
        deallocate(position);
        deallocate(strix_arr_struct);
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        return NULL;
    }

    size_t len = 0;
    size_t substr_len = strlen(substr);

    if (position->pos[0] > 0)
    {
        strix_t *first_part = strix_slice(strix, 0, position->pos[0] - 1);
        if (!is_strix_null(first_part))
        {
            strix_arr_struct->strix_arr[len++] = first_part;
        }
    }

    for (size_t counter = 0; counter < position->len; counter++)
    {
        strix_t *substrix;
        size_t start = position->pos[counter] + substr_len;

        if (counter + 1 == position->len)
        {
            if (start < strix->len)
            {
                substrix = strix_slice(strix, start, strix->len - 1);
            }
            else
            {
                continue;
            }
        }
        else
        {
            if (start < position->pos[counter + 1])
            {
                substrix = strix_slice(strix, start, position->pos[counter + 1] - 1);
            }
            else
            {
                continue;
            }
        }

        if (is_strix_null(substrix) && strix_errno == STRIX_ERR_INVALID_BOUNDS)
        {
            continue;
        }
        if (is_strix_null(substrix))
        {
            for (size_t i = 0; i < len; i++)
            {
                deallocate(strix_arr_struct->strix_arr[i]->str);
                deallocate(strix_arr_struct->strix_arr[i]);
            }
            deallocate(strix_arr_struct->strix_arr);
            deallocate(strix_arr_struct);
            deallocate(position);
            return NULL;
        }
        strix_arr_struct->strix_arr[len++] = substrix;
    }

    strix_arr_struct->len = len;
    deallocate(position);
    strix_errno = STRIX_SUCCESS;
    return strix_arr_struct;
}

strix_arr_t *strix_split_by_substrix(const strix_t *strix, const strix_t *substrix)
{
    if (is_strix_null(strix) || is_strix_null(substrix))
    {
        strix_errno = STRIX_ERR_NULL_PTR;
        return NULL;
    }
    if (is_strix_str_null(strix) || is_strix_str_null(substrix))
    {
        strix_errno = STRIX_ERR_STRIX_STR_NULL;
        return NULL;
    }

    position_t *position = strix_find_subtrix_all(strix, substrix);
    if (!position)
    {
        return NULL;
    }
    if (position->len == -1)
    {
        deallocate(position);
        return NULL;
    }

    strix_arr_t *strix_arr_struct = (strix_arr_t *)allocate(sizeof(strix_arr_t));
    if (!strix_arr_struct)
    {
        deallocate(position);
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        return NULL;
    }

    if (position->len == -2)
    {
        strix_t *copy = strix_duplicate(strix);
        if (!copy)
        {
            deallocate(position);
            deallocate(strix_arr_struct);
            return NULL;
        }
        strix_arr_struct->len = 1;
        strix_arr_struct->strix_arr = (strix_t **)allocate(sizeof(strix_t *));
        if (!strix_arr_struct->strix_arr)
        {
            deallocate(position);
            deallocate(copy);
            deallocate(strix_arr_struct);
            strix_errno = STRIX_ERR_MALLOC_FAILED;
            return NULL;
        }
        strix_arr_struct->strix_arr[0] = copy;
        deallocate(position);
        return strix_arr_struct;
    }

    strix_arr_struct->strix_arr = (strix_t **)allocate(sizeof(strix_t *) * MAX_SUBSTRIX_NUM);
    if (!strix_arr_struct->strix_arr)
    {
        deallocate(position);
        deallocate(strix_arr_struct);
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        return NULL;
    }

    size_t len = 0;
    size_t substr_len = substrix->len;

    if (position->pos[0] > 0)
    {
        strix_t *first_part = strix_slice(strix, 0, position->pos[0] - 1);
        if (!is_strix_null(first_part))
        {
            strix_arr_struct->strix_arr[len++] = first_part;
        }
    }

    for (size_t counter = 0; counter < position->len; counter++)
    {
        strix_t *substrix;
        size_t start = position->pos[counter] + substr_len;

        if (counter + 1 == position->len)
        {
            if (start < strix->len)
            {
                substrix = strix_slice(strix, start, strix->len - 1);
            }
            else
            {
                continue;
            }
        }
        else
        {
            if (start < position->pos[counter + 1])
            {
                substrix = strix_slice(strix, start, position->pos[counter + 1] - 1);
            }
            else
            {
                continue;
            }
        }

        if (is_strix_null(substrix) && strix_errno == STRIX_ERR_INVALID_BOUNDS)
        {
            continue;
        }
        if (is_strix_null(substrix))
        {
            for (size_t i = 0; i < len; i++)
            {
                deallocate(strix_arr_struct->strix_arr[i]->str);
                deallocate(strix_arr_struct->strix_arr[i]);
            }
            deallocate(strix_arr_struct->strix_arr);
            deallocate(strix_arr_struct);
            deallocate(position);
            return NULL;
        }
        strix_arr_struct->strix_arr[len++] = substrix;
    }

    strix_arr_struct->len = len;
    deallocate(position);
    strix_errno = STRIX_SUCCESS;
    return strix_arr_struct;
}

#undef MAX_SUBSTRIX_NUM
#undef MAX_POSITIONS

strix_t *strix_join_via_delim(const strix_t **strix_arr, size_t len, const char delim)
{
    if (!strix_arr || !len)
    {
        strix_errno = STRIX_ERR_NULL_PTR;
        return NULL;
    }

    size_t total_len = 0;
    for (size_t i = 0; i < len; i++)
    {
        if (is_strix_null(strix_arr[i]))
        {
            strix_errno = STRIX_ERR_NULL_PTR;
            return NULL;
        }
        total_len += strix_arr[i]->len;
    }
    total_len += len - 1; // add space for delimiters

    strix_t *result = (strix_t *)allocate(sizeof(strix_t));
    if (!result)
    {
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        return NULL;
    }

    result->str = (char *)allocate(sizeof(char) * total_len);
    if (!result->str)
    {
        deallocate(result);
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        return NULL;
    }
    result->len = total_len;

    char *ptr = result->str;
    for (size_t i = 0; i < len; i++)
    {
        if (!memcpy(ptr, strix_arr[i]->str, strix_arr[i]->len))
        {
            strix_errno = STRIX_ERR_MEMCPY_FAILED;
            return NULL;
        }
        ptr += strix_arr[i]->len;
        if (i < len - 1)
        {
            *ptr = delim;
            ptr++;
        }
    }

    strix_errno = STRIX_SUCCESS;

    return result;
}

strix_t *strix_join_via_substr(const strix_t **strix_arr, size_t len, const char *substr)
{
    if (!strix_arr || !len || !substr)
    {
        strix_errno = STRIX_ERR_NULL_PTR;
        return NULL;
    }

    size_t substr_len = strlen(substr);
    size_t total_len = 0;
    for (size_t i = 0; i < len; i++)
    {
        if (is_strix_null(strix_arr[i]))
        {
            strix_errno = STRIX_ERR_NULL_PTR;
            return NULL;
        }
        total_len += strix_arr[i]->len;
    }
    total_len += (len - 1) * substr_len;

    strix_t *result = (strix_t *)allocate(sizeof(strix_t));
    if (!result)
    {
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        return NULL;
    }

    result->str = (char *)allocate(sizeof(char) * total_len);
    if (!result->str)
    {
        deallocate(result);
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        return NULL;
    }
    result->len = total_len;

    char *ptr = result->str;
    for (size_t i = 0; i < len; i++)
    {
        if (!memcpy(ptr, strix_arr[i]->str, strix_arr[i]->len))
        {
            strix_errno = STRIX_ERR_MEMCPY_FAILED;
            return NULL;
        }
        ptr += strix_arr[i]->len;
        if (i < len - 1)
        {
            if (!memcpy(ptr, substr, substr_len))
            {
                strix_errno = STRIX_ERR_MEMCPY_FAILED;
                return NULL;
            }
            ptr += substr_len;
        }
    }
    strix_errno = STRIX_SUCCESS;

    return result;
}

strix_t *strix_join_via_substrix(const strix_t **strix_arr, size_t len, const strix_t *substrix)
{
    if (!strix_arr || !len || is_strix_null(substrix))
    {
        strix_errno = STRIX_ERR_NULL_PTR;
        return NULL;
    }

    size_t total_len = 0;
    for (size_t i = 0; i < len; i++)
    {
        if (is_strix_null(strix_arr[i]))
        {
            strix_errno = STRIX_ERR_NULL_PTR;
            return NULL;
        }
        total_len += strix_arr[i]->len;
    }
    total_len += (len - 1) * substrix->len;

    strix_t *result = (strix_t *)allocate(sizeof(strix_t));
    if (!result)
    {
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        return NULL;
    }

    result->str = (char *)allocate(sizeof(char) * total_len);
    if (!result->str)
    {
        deallocate(result);
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        return NULL;
    }
    result->len = total_len;

    char *ptr = result->str;
    for (size_t i = 0; i < len; i++)
    {
        if (!memcpy(ptr, strix_arr[i]->str, strix_arr[i]->len))
        {
            strix_errno = STRIX_ERR_MEMCPY_FAILED;
            return NULL;
        }
        ptr += strix_arr[i]->len;
        if (i < len - 1)
        {
            if (!memcpy(ptr, substrix->str, substrix->len))
            {
                strix_errno = STRIX_ERR_MEMCPY_FAILED;
                return NULL;
            }
            ptr += substrix->len;
        }
    }

    strix_errno = STRIX_SUCCESS;
    return result;
}

bool strix_trim_whitespace(strix_t *strix)
{
    if (is_strix_null(strix))
    {
        strix_errno = STRIX_ERR_NULL_PTR;
        return false;
    }
    if (is_strix_str_null(strix))
    {
        strix_errno = STRIX_ERR_STRIX_STR_NULL;
        return false;
    }
    if (strix->len == 0)
    {
        return true;
    }

    size_t start = 0;
    while (start < strix->len && isspace((unsigned char)strix->str[start]))
    {
        start++;
    }

    if (start == strix->len)
    {
        deallocate(strix->str);
        strix->str = NULL;
        strix->len = 0;
        return true;
    }

    size_t end = strix->len - 1;
    while (end > start && isspace((unsigned char)strix->str[end]))
    {
        end--;
    }

    size_t new_len = end - start + 1;
    char *new_str = allocate(new_len);
    if (!new_str)
    {
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        return false;
    }

    if (memcpy(new_str, strix->str + start, new_len) == NULL)
    {
        deallocate(new_str);
        strix_errno = STRIX_ERR_MEMCPY_FAILED;
        return false;
    }

    deallocate(strix->str);
    strix->str = new_str;
    strix->len = new_len;
    return true;
}

bool strix_trim_char(strix_t *strix, const char trim)
{
    if (is_strix_null(strix))
    {
        strix_errno = STRIX_ERR_NULL_PTR;
        return false;
    }
    if (is_strix_str_null(strix))
    {
        strix_errno = STRIX_ERR_STRIX_STR_NULL;
        return false;
    }
    if (strix->len == 0)
    {
        return true;
    }

    size_t start = 0;
    while (start < strix->len && strix->str[start] == trim)
    {
        start++;
    }

    if (start == strix->len)
    {
        deallocate(strix->str);
        strix->str = NULL;
        strix->len = 0;
        return true;
    }

    size_t end = strix->len - 1;
    while (end > start && strix->str[end] == trim)
    {
        end--;
    }

    size_t new_len = end - start + 1;
    char *new_str = allocate(new_len);
    if (!new_str)
    {
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        return false;
    }

    if (memcpy(new_str, strix->str + start, new_len) == NULL)
    {
        deallocate(new_str);
        strix_errno = STRIX_ERR_MEMCPY_FAILED;
        return false;
    }

    deallocate(strix->str);
    strix->str = new_str;
    strix->len = new_len;
    return true;
}

double strix_to_double(strix_t *strix)
{
    double num = 0;
    double fraction_part = 0;
    bool is_neg = false;
    bool in_fraction = false;
    double divisor = 1;
    strix_errno = STRIX_SUCCESS;

    for (size_t i = 0; i < strix->len; i++)
    {
        char ch = strix->str[i];

        if (ch == '-')
        {
            if (i > 0)
            {
                strix_errno = STRIX_ERR_INVALID_DOUBLE;
                return -1;
            }
            is_neg = true;
            continue;
        }

        if (ch == '+')
        {
            if (i > 0)
            {
                strix_errno = STRIX_ERR_INVALID_DOUBLE;
                return -1;
            }
            continue;
        }

        if (ch == '.')
        {
            if (in_fraction)
            {
                strix_errno = STRIX_ERR_INVALID_DOUBLE;
                return -1;
            }
            in_fraction = true;
            continue;
        }

        int dig = ch - '0';
        if (dig < 0 || dig > 9)
        {
            strix_errno = STRIX_ERR_INVALID_DOUBLE;
            return -1;
        }

        if (in_fraction)
        {
            divisor *= 10;
            fraction_part += dig / divisor;
        }
        else
        {
            num = num * 10 + dig;
        }
    }

    double result = num + fraction_part;
    return is_neg ? -result : result;
}

uint64_t strix_to_unsigned_int(strix_t *strix)
{
    strix_errno = STRIX_SUCCESS;
    uint64_t num = 0;

    for (size_t i = 0; i < strix->len; i++)
    {
        char ch = strix->str[i];

        if (ch == '+')
        {
            if (i > 0)
            {
                strix_errno = STRIX_ERR_INVALID_INT;
                return 0;
            }
            continue;
        }

        int dig = ch - '0';
        if (dig < 0 || dig > 9)
        {
            strix_errno = STRIX_ERR_INVALID_INT;
            return 0;
        }

        if (num > (UINT64_MAX - dig) / 10)
        {
            strix_errno = STRIX_ERR_INT_OVERFLOW;
            return 0;
        }

        num = num * 10 + dig;
    }

    return num;
}

int64_t strix_to_signed_int(strix_t *strix)
{
    strix_errno = STRIX_SUCCESS;
    bool is_neg = false;
    int64_t num = 0;

    for (size_t i = 0; i < strix->len; i++)
    {
        char ch = strix->str[i];

        if (ch == '+')
        {
            if (i > 0)
            {
                strix_errno = STRIX_ERR_INVALID_INT;
                return 0;
            }
            continue;
        }

        if (ch == '-')
        {
            if (i > 0)
            {
                strix_errno = STRIX_ERR_INVALID_INT;
                return 0;
            }
            is_neg = true;
            continue;
        }

        int dig = ch - '0';
        if (dig < 0 || dig > 9)
        {
            strix_errno = STRIX_ERR_INVALID_INT;
            return 0;
        }

        if (num > (INT64_MAX - dig) / 10)
        {
            strix_errno = STRIX_ERR_INT_OVERFLOW;
            return 0;
        }

        num = num * 10 + dig;
    }

    return is_neg ? -num : num;
}

int64_t strix_count_char(const strix_t *strix, const char chr)
{
    if (is_strix_null(strix))
    {
        strix_errno = STRIX_ERR_NULL_PTR;
        return -1;
    }

    if (is_strix_str_null(strix))
    {
        strix_errno = STRIX_ERR_STRIX_STR_NULL;
        return -1;
    }

    int64_t count = 0;
    for (size_t counter = 0; counter < strix->len; counter++)
    {
        if (strix->str[counter] == chr)
        {
            count++;
        }
    }

    return count;
}

int64_t strix_count_substr(const strix_t *strix, const char *substr)
{
    if (is_strix_null(strix) || is_str_null(substr))
    {
        strix_errno = STRIX_ERR_NULL_PTR;
        return -1;
    }
    if (is_strix_str_null(strix))
    {
        strix_errno = STRIX_ERR_STRIX_STR_NULL;
        return -1;
    }

    return kmp_search_all_len(substr, strix->str, strlen(substr), strix->len);
}

int64_t strix_count_substrix(const strix_t *strix, const strix_t *substrix)
{
    if (is_strix_null(strix) || is_strix_null(substrix))
    {
        strix_errno = STRIX_ERR_NULL_PTR;
        return -1;
    }
    if (is_strix_str_null(strix) || is_strix_str_null(substrix))
    {
        strix_errno = STRIX_ERR_STRIX_STR_NULL;
        return -1;
    }

    return kmp_search_all_len(substrix->str, strix->str, substrix->len, strix->len);
}

strix_t *strix_slice_by_stride(const strix_t *strix, size_t start, size_t end, size_t stride)
{
    if (start > end || end >= strix->len || is_strix_null(strix))
    {
        strix_errno = start > end || end >= strix->len ? STRIX_ERR_INVALID_BOUNDS : STRIX_ERR_NULL_PTR;
        return NULL;
    }

    if (stride == 0)
    {
        strix_errno = STRIX_ERR_INVALID_STRIDE;
        return NULL;
    }

    size_t range = end - start + 1;
    size_t slice_len = (range + stride - 1) / stride; // Ceiling division

    strix_t *slice = (strix_t *)allocate(sizeof(strix_t));
    if (is_strix_null(slice))
    {
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        return NULL;
    }

    slice->len = slice_len;
    slice->str = (char *)allocate(sizeof(char) * slice_len);
    if (!slice->str)
    {
        deallocate(slice);
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        return NULL;
    }

    for (size_t i = 0, src_idx = start; i < slice_len; i++, src_idx += stride)
    {
        slice->str[i] = strix->str[src_idx];
    }

    strix_errno = STRIX_SUCCESS;
    return slice;
}

char_arr_t *strix_find_unique_char(strix_t *strix)
{
    if (is_strix_null(strix))
    {
        strix_errno = STRIX_ERR_NULL_PTR;
        return NULL;
    }

    if (is_strix_str_null(strix))
    {
        strix_errno = STRIX_ERR_STRIX_STR_NULL;
        return NULL;
    }

#define MAX_UNIQUE 128

    char *unique_char_arr = (char *)allocate(MAX_UNIQUE * sizeof(char));
    if (!unique_char_arr)
    {
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        return NULL;
    }

    char_arr_t *char_arr = (char_arr_t *)allocate(sizeof(char_arr_t));
    if (!char_arr)
    {
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        return NULL;
    }

    char_arr->len = 0;
    char_arr->unique_char_arr = unique_char_arr;

    bool found[MAX_UNIQUE] = {false};

    for (size_t counter = 0; counter < strix->len; counter++)
    {
        if (!found[strix->str[counter]])
        {
            found[strix->str[counter]] = true;
            char_arr->unique_char_arr[char_arr->len++] = strix->str[counter];
        }
    }

    return char_arr;
}

#undef MAX_UNIQUE

bool strix_delete_occurence(strix_t *strix, const char *substr)
{
    if (is_strix_null(strix) || is_str_null(substr))
    {
        strix_errno = STRIX_ERR_NULL_PTR;
        return false;
    }

    if (is_strix_str_null(strix))
    {
        strix_errno = STRIX_ERR_STRIX_STR_NULL;
        return false;
    }

    position_t *positions = strix_find_all(strix, substr);
    if (positions == NULL)
    {
        strix_errno = STRIX_SUCCESS;
        return true;
    }

    size_t substr_len = strlen(substr);
    size_t new_len = strix->len - (substr_len * positions->len);

    char *new_str = (char *)allocate((new_len) * sizeof(char));
    if (new_str == NULL)
    {
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        return false;
    }

    size_t current_pos = 0;
    size_t copy_pos = 0;

    for (int64_t i = 0; i < positions->len; i++)
    {
        size_t substr_pos = positions->pos[i];
        size_t copy_len = substr_pos - current_pos;

        if (memcpy(new_str + copy_pos, strix->str + current_pos, copy_len) == NULL)
        {
            deallocate(new_str);
            strix_errno = STRIX_ERR_MEMCPY_FAILED;
            return false;
        }

        copy_pos += copy_len;
        current_pos = substr_pos + substr_len;
    }

    if (current_pos < strix->len)
    {
        if (memcpy(new_str + copy_pos, strix->str + current_pos, strix->len - current_pos) == NULL)
        {
            deallocate(new_str);
            strix_errno = STRIX_ERR_MEMCPY_FAILED;
            return false;
        }
    }

    deallocate(strix->str);
    strix->str = new_str;
    strix->len = new_len;

    strix_errno = STRIX_SUCCESS;
    return true;
}

void strix_free_char_arr(char_arr_t *char_arr)
{
    if (!char_arr || !char_arr->unique_char_arr)
    {
        return;
    }

    deallocate(char_arr->unique_char_arr);
    deallocate(char_arr);
}

position_t *strix_find_all_char(const strix_t *strix, const char chr)
{
    if (is_strix_null(strix))
    {
        strix_errno = STRIX_ERR_NULL_PTR;
        return NULL;
    }

    if (is_strix_str_null(strix))
    {
        strix_errno = STRIX_ERR_STRIX_STR_NULL;
        return NULL;
    }

    position_t *posn = (position_t *)malloc(sizeof(position_t));
    if (!posn)
    {
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        return false;
    }

#define MAX_POSITIONS 1024
    size_t *pos_arr = (size_t *)malloc(sizeof(size_t) * MAX_POSITIONS);
    if (!pos_arr)
    {
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        return NULL;
    }
#undef MAX_POSITIONS

    size_t len = 0;

    for (size_t counter = 0; counter < strix->len; counter++)
    {
        if (strix->str[counter] == chr)
        {
            pos_arr[len++] = counter;
        }
    }

    posn->pos = pos_arr;
    posn->len = len;

    return posn;
}

strix_t *conv_file_to_strix(const char *file_path)
{
    if (!file_path)
    {
        strix_errno = STRIX_ERR_NULL_PTR;
        return NULL;
    }

    FILE *input_file = fopen(file_path, "r");
    if (!input_file)
    {
        strix_errno = STRIX_ERR_STDIO;
        return NULL;
    }

    if (fseek(input_file, 0, SEEK_END) != 0)
    {
        strix_errno = STRIX_ERR_STDIO;
        return NULL;
    }

    long input_file_len = ftell(input_file);
    if (input_file_len < 0)
    {
        strix_errno = STRIX_ERR_STDIO;
        fclose(input_file);
        return NULL;
    }

    if (fseek(input_file, 0, SEEK_SET) != 0)
    {
        strix_errno = STRIX_ERR_STDIO;
        fclose(input_file);
        return NULL;
    }

    uint8_t *input_file_array = (uint8_t *)allocate((input_file_len + 1) * sizeof(uint8_t));
    if (!input_file_array)
    {
        strix_errno = STRIX_ERR_MALLOC_FAILED;
        fclose(input_file);
        return NULL;
    }
    input_file_array[input_file_len] = '\0';

    size_t bytes_read = fread(input_file_array, 1, input_file_len, input_file);
    if (bytes_read != (size_t)input_file_len)
    {
        strix_errno = STRIX_ERR_STDIO;
        deallocate(input_file_array);
        fclose(input_file);
        return NULL;
    }
    fclose(input_file);

    strix_t *input_strix = strix_create((const char *)input_file_array);
    deallocate(input_file_array);
    if (!input_strix)
    {
        return NULL;
    }

    return input_strix;
}

void strix_free_position(position_t *pos)
{
    if (!pos)
    {
        return;
    }

    free(pos->pos);
    free(pos);
}