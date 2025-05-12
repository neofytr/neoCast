#ifndef VECTOR_H
#define VECTOR_H

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

/**
 * @file vector.h
 * @brief A generic, dynamic array implementation in C using macros.
 *
 * This header provides a set of macros for creating and manipulating
 * dynamic arrays (vectors) in C. The implementation uses void pointers
 * to allow storage of any data type.
 *
 * @note The vector stores pointers to elements, not the elements themselves.
 * @note This implementation automatically handles memory allocation and resizing.
 */

/**
 * @brief Structure definition for a generic vector.
 *
 * The vector maintains three key pieces of information:
 * - items: An array of void pointers to the stored elements
 * - count: The current number of elements in the vector
 * - capacity: The total allocated capacity of the vector
 */
typedef struct
{
    void **items;    /**< Array of stored elements (pointers) */
    size_t count;    /**< Number of elements currently in the vector */
    size_t capacity; /**< Allocated size of the vector */
} vector_t;

/**
 * @brief Macro to initialize an empty vector.
 *
 * Use this macro to initialize a vector with zero elements and zero capacity.
 * Memory will be allocated on the first append operation.
 *
 * @example
 * vector_t my_vector = NEOVEC_INIT;
 */
#define NEOVEC_INIT {NULL, 0, 0}

/**
 * @brief Macro to append an element to a vector.
 *
 * This macro adds a new element to the end of the vector. If the vector
 * is at capacity, it automatically doubles the capacity by reallocating
 * memory before adding the element.
 *
 * @param vector_ptr Pointer to the vector
 * @param element Element to be appended (will be cast to void*)
 *
 * @note If memory allocation fails, the program exits with EXIT_FAILURE
 *
 * @example
 * int *value = malloc(sizeof(int));
 * *value = 42;
 * neovec_append(&my_vector, value);
 */
#define neovec_append(vector_ptr, element)                                                               \
    do                                                                                                   \
    {                                                                                                    \
        if ((vector_ptr)->count >= (vector_ptr)->capacity)                                               \
        {                                                                                                \
            (vector_ptr)->capacity = (!((vector_ptr)->capacity)) ? 1 : (vector_ptr)->capacity * 2;       \
            (vector_ptr)->items = realloc((vector_ptr)->items, (vector_ptr)->capacity * sizeof(void *)); \
            if (!(vector_ptr)->items)                                                                    \
            {                                                                                            \
                exit(EXIT_FAILURE); /* Handle memory allocation failure */                               \
            }                                                                                            \
        }                                                                                                \
        (vector_ptr)->items[(vector_ptr)->count++] = (element);                                          \
    } while (0)

/**
 * @brief Macro to append an array of elements to a vector.
 *
 * This macro iterates through the given array and appends each element
 * to the vector individually using neovec_append.
 *
 * @param vector_ptr Pointer to the vector
 * @param element_arr Array of elements to be appended
 * @param count Number of elements in the array
 *
 * @example
 * int *values[3] = {&val1, &val2, &val3};
 * neovec_append_all(&my_vector, values, 3);
 */
#define neovec_append_all(vector_ptr, element_arr, count)      \
    do                                                         \
    {                                                          \
        for (size_t index = 0; index < (count); index++)       \
        {                                                      \
            neovec_append((vector_ptr), (element_arr)[index]); \
        }                                                      \
    } while (0)

/**
 * @brief Macro for iterating over elements in a vector.
 *
 * This macro provides a convenient way to iterate through all elements
 * in the vector with proper type casting.
 *
 * @param type_element The type of elements stored in the vector
 * @param element_ptr Name for the pointer variable to be used in the loop
 * @param vector_ptr Pointer to the vector
 *
 * @example
 * neovec_foreach(int, num, &my_vector) {
 *     printf("%d\n", *num);
 * }
 */
#define neovec_foreach(type_element, element_ptr, vector_ptr)       \
    for (type_element * (element_ptr) = (vector_ptr)->items;        \
         (element_ptr) < (vector_ptr)->items + (vector_ptr)->count; \
         (element_ptr)++)

/**
 * @brief Macro to get an element at a specific index in the vector.
 *
 * This macro retrieves an element at the specified index with type casting.
 *
 * @param type_element The type of the element to retrieve
 * @param vector_ptr Pointer to the vector
 * @param index Index of the element to retrieve
 *
 * @return The element at the specified index cast to the specified type
 *
 * @example
 * int *value = neovec_get(int, &my_vector, 0);
 */
#define neovec_get(type_element, vector_ptr, index) \
    ((index) < (vector_ptr)->count ? ((type_element *)((vector_ptr)->items[index])) : NULL)

/**
 * @brief Macro to set an element at a specific index in the vector.
 *
 * This macro replaces an element at the specified index with a new value.
 *
 * @param vector_ptr Pointer to the vector
 * @param index Index where the element should be set
 * @param element New element to set at the specified index
 *
 * @example
 * int *new_value = malloc(sizeof(int));
 * *new_value = 100;
 * neovec_set(&my_vector, 0, new_value);
 */
#define neovec_set(vector_ptr, index, element)      \
    do                                              \
    {                                               \
        if ((index) < (vector_ptr)->count)          \
        {                                           \
            (vector_ptr)->items[index] = (element); \
        }                                           \
    } while (0)

/**
 * @brief Macro to remove an element at a specific index from the vector.
 *
 * This macro removes an element at the specified index and shifts all
 * subsequent elements one position to the left.
 *
 * @param vector_ptr Pointer to the vector
 * @param index Index of the element to remove
 *
 * @example
 * neovec_remove(&my_vector, 0);
 */
#define neovec_remove(vector_ptr, index)                                            \
    do                                                                              \
    {                                                                               \
        if ((index) < (vector_ptr)->count)                                          \
        {                                                                           \
            memmove(&(vector_ptr)->items[index], &(vector_ptr)->items[(index) + 1], \
                    ((vector_ptr)->count - (index) - 1) * sizeof(void *));          \
            (vector_ptr)->count--;                                                  \
        }                                                                           \
    } while (0)

/**
 * @brief Macro to clear all elements from a vector.
 *
 * This macro resets the count to zero but maintains the allocated capacity.
 *
 * @param vector_ptr Pointer to the vector
 *
 * @example
 * neovec_clear(&my_vector);
 */
#define neovec_clear(vector_ptr) \
    do                           \
    {                            \
        (vector_ptr)->count = 0; \
    } while (0)

/**
 * @brief Macro to free all memory used by a vector.
 *
 * This macro frees the memory allocated for the items array and
 * resets all vector properties.
 *
 * @param vector_ptr Pointer to the vector
 *
 * @note This does not free the memory of individual elements
 *
 * @example
 * neovec_free(&my_vector);
 */
#define neovec_free(vector_ptr)     \
    do                              \
    {                               \
        free((vector_ptr)->items);  \
        (vector_ptr)->items = NULL; \
        (vector_ptr)->count = 0;    \
        (vector_ptr)->capacity = 0; \
    } while (0)

/**
 * @brief Macro to free all memory used by a vector and its elements.
 *
 * This macro frees the memory of each element and then frees the vector itself.
 *
 * @param vector_ptr Pointer to the vector
 *
 * @example
 * neovec_free_all(&my_vector);
 */
#define neovec_free_all(vector_ptr)                      \
    do                                                   \
    {                                                    \
        for (size_t i = 0; i < (vector_ptr)->count; i++) \
        {                                                \
            free((vector_ptr)->items[i]);                \
        }                                                \
        neovec_free(vector_ptr);                         \
    } while (0)

/**
 * @brief Macro to insert an element at a specific index in the vector.
 *
 * This macro inserts an element at the specified index and shifts all
 * subsequent elements one position to the right.
 *
 * @param vector_ptr Pointer to the vector
 * @param index Index where the element should be inserted
 * @param element Element to insert
 *
 * @example
 * int *value = malloc(sizeof(int));
 * *value = 42;
 * neovec_insert(&my_vector, 0, value);
 */
#define neovec_insert(vector_ptr, index, element)                                                            \
    do                                                                                                       \
    {                                                                                                        \
        if ((index) <= (vector_ptr)->count)                                                                  \
        {                                                                                                    \
            if ((vector_ptr)->count >= (vector_ptr)->capacity)                                               \
            {                                                                                                \
                (vector_ptr)->capacity = ((vector_ptr)->capacity == 0) ? 1 : (vector_ptr)->capacity * 2;     \
                (vector_ptr)->items = realloc((vector_ptr)->items, (vector_ptr)->capacity * sizeof(void *)); \
                if (!(vector_ptr)->items)                                                                    \
                {                                                                                            \
                    exit(EXIT_FAILURE);                                                                      \
                }                                                                                            \
            }                                                                                                \
            memmove(&(vector_ptr)->items[(index) + 1], &(vector_ptr)->items[index],                          \
                    ((vector_ptr)->count - (index)) * sizeof(void *));                                       \
            (vector_ptr)->items[index] = (element);                                                          \
            (vector_ptr)->count++;                                                                           \
        }                                                                                                    \
    } while (0)

/**
 * @brief Macro to find the index of an element in the vector.
 *
 * This macro searches for an element in the vector using pointer comparison.
 *
 * @param vector_ptr Pointer to the vector
 * @param element Element to find
 * @param result_index Variable to store the resulting index
 *
 * @example
 * size_t index;
 * if (neovec_find(&my_vector, element_ptr, &index)) {
 *     printf("Found at index %zu\n", index);
 * }
 */
#define neovec_find(vector_ptr, element, result_index)   \
    ({                                                   \
        bool found = false;                              \
        for (size_t i = 0; i < (vector_ptr)->count; i++) \
        {                                                \
            if ((vector_ptr)->items[i] == (element))     \
            {                                            \
                *(result_index) = i;                     \
                found = true;                            \
                break;                                   \
            }                                            \
        }                                                \
        found;                                           \
    })

/**
 * @brief Macro to resize a vector to a specific capacity.
 *
 * This macro changes the capacity of the vector. If the new capacity
 * is smaller than the current count, elements will be truncated.
 *
 * @param vector_ptr Pointer to the vector
 * @param new_capacity New capacity for the vector
 *
 * @example
 * neovec_resize(&my_vector, 20);
 */
#define neovec_resize(vector_ptr, new_capacity)                                              \
    do                                                                                       \
    {                                                                                        \
        (vector_ptr)->items = realloc((vector_ptr)->items, (new_capacity) * sizeof(void *)); \
        if (!(vector_ptr)->items && (new_capacity) > 0)                                      \
        {                                                                                    \
            exit(EXIT_FAILURE);                                                              \
        }                                                                                    \
        (vector_ptr)->capacity = (new_capacity);                                             \
        if ((vector_ptr)->count > (vector_ptr)->capacity)                                    \
        {                                                                                    \
            (vector_ptr)->count = (vector_ptr)->capacity;                                    \
        }                                                                                    \
    } while (0)

/**
 * @brief Macro to check if a vector is empty.
 *
 * @param vector_ptr Pointer to the vector
 * @return true if the vector is empty, false otherwise
 *
 * @example
 * if (neovec_is_empty(&my_vector)) {
 *     printf("Vector is empty\n");
 * }
 */
#define neovec_is_empty(vector_ptr) ((vector_ptr)->count == 0)

/**
 * @brief Macro to get the current size of a vector.
 *
 * @param vector_ptr Pointer to the vector
 * @return The number of elements in the vector
 *
 * @example
 * size_t size = neovec_size(&my_vector);
 */
#define neovec_size(vector_ptr) ((vector_ptr)->count)

/**
 * @brief Macro to get the current capacity of a vector.
 *
 * @param vector_ptr Pointer to the vector
 * @return The capacity of the vector
 *
 * @example
 * size_t capacity = neovec_capacity(&my_vector);
 */
#define neovec_capacity(vector_ptr) ((vector_ptr)->capacity)

/**
 * @brief Macro to reserve capacity for a vector.
 *
 * This macro ensures that the vector has at least the specified capacity.
 * If the current capacity is already greater, nothing happens.
 *
 * @param vector_ptr Pointer to the vector
 * @param min_capacity Minimum capacity to ensure
 *
 * @example
 * neovec_reserve(&my_vector, 100);
 */
#define neovec_reserve(vector_ptr, min_capacity)                                                         \
    do                                                                                                   \
    {                                                                                                    \
        if ((vector_ptr)->capacity < (min_capacity))                                                     \
        {                                                                                                \
            (vector_ptr)->capacity = (min_capacity);                                                     \
            (vector_ptr)->items = realloc((vector_ptr)->items, (vector_ptr)->capacity * sizeof(void *)); \
            if (!(vector_ptr)->items)                                                                    \
            {                                                                                            \
                exit(EXIT_FAILURE);                                                                      \
            }                                                                                            \
        }                                                                                                \
    } while (0)

/**
 * @brief Macro to shrink a vector's capacity to fit its size.
 *
 * This macro reduces the capacity of the vector to match its count,
 * minimizing memory usage.
 *
 * @param vector_ptr Pointer to the vector
 *
 * @example
 * neovec_shrink_to_fit(&my_vector);
 */
#define neovec_shrink_to_fit(vector_ptr)                                                                 \
    do                                                                                                   \
    {                                                                                                    \
        if ((vector_ptr)->count < (vector_ptr)->capacity)                                                \
        {                                                                                                \
            (vector_ptr)->capacity = (vector_ptr)->count > 0 ? (vector_ptr)->count : 1;                  \
            (vector_ptr)->items = realloc((vector_ptr)->items, (vector_ptr)->capacity * sizeof(void *)); \
            if (!(vector_ptr)->items && (vector_ptr)->capacity > 0)                                      \
            {                                                                                            \
                exit(EXIT_FAILURE);                                                                      \
            }                                                                                            \
        }                                                                                                \
    } while (0)

/**
 * @brief Macro to create a copy of a vector.
 *
 * This macro creates a new vector with the same elements as the source vector.
 *
 * @param dest_ptr Pointer to the destination vector
 * @param src_ptr Pointer to the source vector
 *
 * @note This only copies the pointers, not the actual elements
 *
 * @example
 * vector_t copy = NEOVEC_INIT;
 * neovec_copy(&copy, &my_vector);
 */
#define neovec_copy(dest_ptr, src_ptr)                                                  \
    do                                                                                  \
    {                                                                                   \
        neovec_free(dest_ptr);                                                          \
        neovec_reserve(dest_ptr, (src_ptr)->count);                                     \
        memcpy((dest_ptr)->items, (src_ptr)->items, (src_ptr)->count * sizeof(void *)); \
        (dest_ptr)->count = (src_ptr)->count;                                           \
    } while (0)

/**
 * @brief Macro to extend a vector with elements from another vector.
 *
 * This macro appends all elements from the source vector to the destination vector.
 *
 * @param dest_ptr Pointer to the destination vector
 * @param src_ptr Pointer to the source vector
 *
 * @example
 * neovec_extend(&my_vector, &other_vector);
 */
#define neovec_extend(dest_ptr, src_ptr)                                 \
    do                                                                   \
    {                                                                    \
        neovec_append_all(dest_ptr, (src_ptr)->items, (src_ptr)->count); \
    } while (0)

#endif /* VECTOR_H */