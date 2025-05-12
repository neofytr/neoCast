#include "../inc/dynarr.h"
#include <math.h>

dyn_arr_t *dyn_arr_create(size_t min_size, size_t item_size, void *default_value)
{
    if (!item_size)
    {
        return NULL;
    }

    dyn_arr_t *dyn_arr = (dyn_arr_t *)malloc(sizeof(dyn_arr_t));
    if (!dyn_arr)
    {
        return NULL;
    }

    dyn_arr->item_size = item_size;
    dyn_arr->last_index = 0;
    dyn_arr->is_empty = true;

    if (!default_value)
    {
        dyn_arr->default_value = NULL;
    }
    else
    {
        dyn_arr->default_value = malloc(item_size);
        if (!dyn_arr->default_value)
        {
            free(dyn_arr);
            return NULL;
        }

        if (!memcpy(dyn_arr->default_value, default_value, item_size))
        {
            free(dyn_arr->default_value);
            free(dyn_arr);
            return NULL;
        }
    }

    if (!min_size)
    {
        dyn_arr->len = 0;
        dyn_arr->nodes = NULL;
        return dyn_arr;
    }

    size_t num_of_nodes = min_size / MAX_NODE_SIZE + 1;
    void **nodes = (void **)calloc(num_of_nodes, sizeof(void *));
    if (!nodes)
    {
        free(dyn_arr);
        return NULL;
    }

    for (size_t index = 0; index < num_of_nodes; index++)
    {
        nodes[index] = malloc(MAX_NODE_SIZE * item_size);
        if (!nodes[index])
        {
            for (size_t counter = 0; counter < index; counter++)
            {
                free(nodes[counter]);
                free(nodes);
                free(dyn_arr);
                return NULL;
            }
        }

        if (default_value)
        {
            for (size_t counter = 0; counter < MAX_NODE_SIZE; counter++)
            {
                if (!memcpy((char *)nodes[index] + (counter * item_size), default_value, item_size))
                {
                    for (size_t count = 0; count <= index; count++)
                    {
                        free(nodes[count]);
                    }
                    free(nodes);
                    free(dyn_arr);
                    return NULL;
                }
            }
        }
    }

    dyn_arr->len = num_of_nodes;
    dyn_arr->nodes = nodes;
    return dyn_arr;
}

void dyn_arr_free(dyn_arr_t *dyn_arr)
{
    if (!dyn_arr)
    {
        return;
    }

    for (size_t i = 0; i < dyn_arr->len; i++)
    {
        free(dyn_arr->nodes[i]);
    }

    free(dyn_arr->default_value);
    free(dyn_arr->nodes);
    free(dyn_arr);
}

bool dyn_arr_set(dyn_arr_t *dyn_arr, size_t index, const void *item)
{
    if (!dyn_arr || !item)
    {
        return false;
    }

    if (index > dyn_arr->last_index)
    {
        dyn_arr->last_index = index;
    }

    size_t node_index = index & (MAX_NODE_SIZE - 1);
    size_t node_no = index / MAX_NODE_SIZE;

    if (node_no >= dyn_arr->len)
    {
        size_t new_len = 1U << ((size_t)log2(node_no) + 1U);
        void **new_nodes = (void **)realloc(dyn_arr->nodes, new_len * sizeof(void *));
        if (!new_nodes)
        {
            return false;
        }

        // set all the unallocated node ptrs to NULL
        memset(new_nodes + dyn_arr->len, 0, (new_len - dyn_arr->len) * sizeof(void *));
        dyn_arr->nodes = new_nodes;
        dyn_arr->len = new_len;
    }

    if (!dyn_arr->nodes[node_no])
    {
        dyn_arr->nodes[node_no] = malloc(MAX_NODE_SIZE * dyn_arr->item_size);
        if (!dyn_arr->nodes[node_no])
        {
            return false;
        }

        if (dyn_arr->default_value)
        {
            for (size_t counter = 0; counter < MAX_NODE_SIZE; counter++)
            {
                memcpy((char *)dyn_arr->nodes[node_no] + (counter * dyn_arr->item_size),
                       dyn_arr->default_value, dyn_arr->item_size);
            }
        }
    }

    memcpy((char *)dyn_arr->nodes[node_no] + (node_index * dyn_arr->item_size),
           item, dyn_arr->item_size);

    if (dyn_arr->is_empty)
    {
        dyn_arr->is_empty = false;
    }
    return true;
}

bool dyn_arr_get(dyn_arr_t *dyn_arr, size_t index, void *output)
{
    if (!dyn_arr || !output)
    {
        return false;
    }

    size_t node_no = index / MAX_NODE_SIZE;
    size_t node_index = index & (MAX_NODE_SIZE - 1);

    if (node_no >= dyn_arr->len || !dyn_arr->nodes[node_no])
    {
        return false;
    }

    memcpy(output, (char *)dyn_arr->nodes[node_no] + (node_index * dyn_arr->item_size),
           dyn_arr->item_size);
    return true;
}

bool dyn_arr_max(dyn_arr_t *dyn_arr, size_t start_index, size_t end_index,
                 dyn_compare_t is_less, void *output)
{
    if (!dyn_arr || !output || start_index > end_index)
    {
        return false;
    }

    char buffer[2 * dyn_arr->item_size];
    void *max = buffer;
    void *temp = buffer + dyn_arr->item_size;

    if (!dyn_arr_get(dyn_arr, start_index, max))
    {
        return false;
    }

    for (size_t i = start_index + 1; i <= end_index; i++)
    {
        if (!dyn_arr_get(dyn_arr, i, temp))
        {
            continue;
        }

        if (is_less(max, temp))
        {
            void *swap = max;
            max = temp;
            temp = swap;
        }
    }

    memcpy(output, max, dyn_arr->item_size);
    return true;
}

bool dyn_arr_min(dyn_arr_t *dyn_arr, size_t start_index, size_t end_index,
                 dyn_compare_t is_less, void *output)
{
    if (!dyn_arr || !output || start_index > end_index)
    {
        return false;
    }

    char buffer[2 * dyn_arr->item_size];
    void *min = buffer;
    void *temp = buffer + dyn_arr->item_size;

    if (!dyn_arr_get(dyn_arr, start_index, min))
    {
        return false;
    }

    for (size_t i = start_index + 1; i <= end_index; i++)
    {
        if (!dyn_arr_get(dyn_arr, i, temp))
        {
            continue;
        }

        if (is_less(temp, min))
        {
            void *swap = min;
            min = temp;
            temp = swap;
        }
    }

    memcpy(output, min, dyn_arr->item_size);
    return true;
}

bool dyn_arr_sort(dyn_arr_t *dyn_arr, size_t start_index, size_t end_index, dyn_compare_t compare)
{
    if (!dyn_arr || start_index > end_index)
    {
        return false;
    }

    if (start_index == end_index)
    {
        return true;
    }

    size_t mid = start_index + (end_index - start_index) / 2;

    if (!dyn_arr_sort(dyn_arr, start_index, mid, compare) ||
        !dyn_arr_sort(dyn_arr, mid + 1, end_index, compare))
    {
        return false;
    }

    size_t left_len = mid - start_index + 1;
    size_t right_len = end_index - mid;
    size_t item_size = dyn_arr->item_size;

    void *temp_buffer = malloc((left_len + right_len + 2) * item_size);
    if (!temp_buffer)
    {
        return false;
    }

    void *left_temp = temp_buffer;
    void *right_temp = (char *)temp_buffer + (left_len * item_size);
    void *left_item = (char *)right_temp + (right_len * item_size);
    void *right_item = (char *)left_item + item_size;

    for (size_t i = 0; i < left_len; i++)
    {
        if (!dyn_arr_get(dyn_arr, start_index + i, (char *)left_temp + (i * item_size)))
        {
            free(temp_buffer);
            return false;
        }
    }

    for (size_t i = 0; i < right_len; i++)
    {
        if (!dyn_arr_get(dyn_arr, mid + 1 + i, (char *)right_temp + (i * item_size)))
        {
            free(temp_buffer);
            return false;
        }
    }

    size_t left_index = 0;
    size_t right_index = 0;
    size_t main_index = start_index;

    while (left_index < left_len && right_index < right_len)
    {
        memcpy(left_item, (char *)left_temp + (left_index * item_size), item_size);
        memcpy(right_item, (char *)right_temp + (right_index * item_size), item_size);

        if (compare(left_item, right_item))
        {
            if (!dyn_arr_set(dyn_arr, main_index++, left_item))
            {
                free(temp_buffer);
                return false;
            }
            left_index++;
        }
        else
        {
            if (!dyn_arr_set(dyn_arr, main_index++, right_item))
            {
                free(temp_buffer);
                return false;
            }
            right_index++;
        }
    }

    while (left_index < left_len)
    {
        memcpy(left_item, (char *)left_temp + (left_index * item_size), item_size);
        if (!dyn_arr_set(dyn_arr, main_index++, left_item))
        {
            free(temp_buffer);
            return false;
        }
        left_index++;
    }

    while (right_index < right_len)
    {
        memcpy(right_item, (char *)right_temp + (right_index * item_size), item_size);
        if (!dyn_arr_set(dyn_arr, main_index++, right_item))
        {
            free(temp_buffer);
            return false;
        }
        right_index++;
    }

    free(temp_buffer);
    return true;
}

bool dyn_arr_append(dyn_arr_t *dyn_arr, const void *item)
{
    if (!dyn_arr || !item)
    {
        return false;
    }

    if (dyn_arr->is_empty)
    {
        dyn_arr->is_empty = false;
        return dyn_arr_set(dyn_arr, 0, item);
    }

    return dyn_arr_set(dyn_arr, dyn_arr->last_index + 1, item);
}