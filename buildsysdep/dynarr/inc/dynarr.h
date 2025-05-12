#ifndef DYN_ARR_H
#define DYN_ARR_H

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>

#define MAX_NODE_SIZE (1U << 16) // must be a power of two

typedef struct
{
    size_t len;        // Number of nodes
    size_t last_index; // Index of the last element in the array
    size_t item_size;  // Size of each data item in bytes
    void **nodes;      // Array of node pointers
    void *default_value;
    bool is_empty;
} dyn_arr_t;

// Function pointer type for comparing two items
typedef bool (*dyn_compare_t)(const void *a, const void *b);

/**
 * Creates a new dynamic array
 * @param min_size Minimum capacity of the array
 * @param item_size Size of each item in bytes
 * @return Pointer to the new dynamic array, or NULL if allocation failed
 */
dyn_arr_t *dyn_arr_create(size_t min_size, size_t item_size, void *default_value);

/**
 * Frees all memory associated with the dynamic array
 * @param dyn_arr Pointer to the dynamic array
 */
void dyn_arr_free(dyn_arr_t *dyn_arr);

/**
 * Sets an item at the specified index
 * @param dyn_arr Pointer to the dynamic array
 * @param index Index to set the item at
 * @param item Pointer to the item to copy into the array
 * @return true if successful, false if allocation failed
 */
bool dyn_arr_set(dyn_arr_t *dyn_arr, size_t index, const void *item);

/**
 * Appends an item immediately next to the last occupied index in the array
 * @param dyn_arr Pointer to the dynamic array
 * @param item Pointer to the item to copy into the array
 * @return true if successful, false if append fails
 */
bool dyn_arr_append(dyn_arr_t *dyn_arr, const void *item);

/**
 * Gets a pointer to an item at the specified index
 * @param dyn_arr Pointer to the dynamic array
 * @param index Index to get the item from
 * @param output Pointer to memory where the item will be copied
 * @return true if successful, false if the index is invalid
 */
bool dyn_arr_get(dyn_arr_t *dyn_arr, size_t index, void *output);

/**
 * Sorts items in the dynamic array
 * @param dyn_arr Pointer to the dynamic array
 * @param start_index Starting index (inclusive)
 * @param end_index Ending index (inclusive)
 * @param compare Comparison function that returns true if a should come before b
 * @return true if successful, false if allocation failed or indices are invalid
 */
bool dyn_arr_sort(dyn_arr_t *dyn_arr, size_t start_index, size_t end_index, dyn_compare_t compare);

/**
 * Finds the maximum element in the range
 * @param dyn_arr Pointer to the dynamic array
 * @param start_index Starting index (inclusive)
 * @param end_index Ending index (inclusive)
 * @param is_less Comparison function that returns true if a < b
 * @param output Pointer to memory where the maximum item will be copied
 * @return true if successful, false if indices are invalid
 */
bool dyn_arr_max(dyn_arr_t *dyn_arr, size_t start_index, size_t end_index, dyn_compare_t is_less, void *output);

/**
 * Finds the minimum element in the range
 * @param dyn_arr Pointer to the dynamic array
 * @param start_index Starting index (inclusive)
 * @param end_index Ending index (inclusive)
 * @param is_less Comparison function that returns true if a < b
 * @param output Pointer to memory where the minimum item will be copied
 * @return true if successful, false if indices are invalid
 */
bool dyn_arr_min(dyn_arr_t *dyn_arr, size_t start_index, size_t end_index, dyn_compare_t is_less, void *output);

#endif // DYN_ARR_H