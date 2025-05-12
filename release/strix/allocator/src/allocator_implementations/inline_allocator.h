/**
 * @file mem_alloc.h
 * @brief A modular heap memory allocator with alignment support
 */

#ifndef MEM_ALLOCATOR_H
#define MEM_ALLOCATOR_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "../checksum_implementations/xxh32.h"
#include "../checksum_implementations/crc32.h"

/* Configuration */
#define XXH32_SEED 0xFF32
#define HEAP_CAPACITY (65536) // 64KB heap size
#define SPLIT_THRESHOLD (16)

/* Alignment options */
typedef enum
{
    ALIGN_4 = 4,
    ALIGN_8 = 8,
    ALIGN_16 = 16,
    ALIGN_32 = 32,
    NO_ALIGNMENT = 0,
} alignment_t;

#define DEFAULT_ALIGNMENT (ALIGN_8)
#define MAX_ALIGNMENT (ALIGN_32)
#define DEBUG_LOGGING (1)

/* Public API declarations */
bool heap_init(void);
void *heap_alloc(size_t size, alignment_t alignment);
void *heap_realloc(void *ptr, size_t new_size, alignment_t new_alignment);
void heap_free(void *ptr);
void heap_get_stats(size_t *total_size, size_t *used_size,
                    size_t *free_size, size_t *largest_free_block);

#ifdef MEM_IMPLEMENTATION

/* Internal structures */
typedef struct __attribute__((packed))
{
    void *prev_chunk;
    size_t chunk_size;
    bool is_allocated;
    uint8_t current_alignment;
    uint32_t checksum;
    uint8_t padding[MAX_ALIGNMENT - (sizeof(size_t) + sizeof(bool) +
                                     sizeof(uint32_t) + sizeof(uint8_t) + sizeof(void *))];
} metadata_t;

/* Static assertions */
_Static_assert(sizeof(metadata_t) == MAX_ALIGNMENT,
               "Metadata size must match MAX_ALIGNMENT");

/* Internal state */
static uint8_t heap[HEAP_CAPACITY] __attribute__((aligned(MAX_ALIGNMENT))) = {0};
static bool is_initialized = false;

/* Heap navigation macros */
#define HEAP_START ((uint8_t *)heap)
#define HEAP_END (HEAP_START + HEAP_CAPACITY)
#define NEXT_CHUNK(ptr) ((uint8_t *)(ptr) + sizeof(metadata_t) + \
                         ((metadata_t *)(ptr))->chunk_size)
#define CHUNK_DATA(ptr) ((uint8_t *)(ptr) + sizeof(metadata_t))

/* Alignment helper functions */
static inline size_t align_up(size_t n, size_t align)
{
    return (n + align - 1) & ~(align - 1);
}

static inline void *align_ptr(void *ptr, size_t align)
{
    return (void *)align_up((uintptr_t)ptr, align);
}

static inline alignment_t calculate_alignment(const void *ptr)
{
    uintptr_t chunk_data = (uintptr_t)CHUNK_DATA(ptr);
    for (alignment_t align = ALIGN_32; align >= ALIGN_4; align >>= 1)
    {
        if (!(chunk_data & (align - 1)))
        {
            return align;
        }
    }
    return NO_ALIGNMENT;
}

/* Validation helper functions */
static inline bool is_within_heap(const void *ptr)
{
    return ptr >= (void *)HEAP_START && ptr < (void *)HEAP_END;
}

static inline uint32_t calculate_chunk_checksum(const metadata_t *chunk)
{
    const size_t checksum_size = offsetof(metadata_t, checksum);
#ifdef CRC32
    return crc32((const uint8_t *)chunk, checksum_size);
#else
    return xxh32((const uint8_t *)chunk, checksum_size, XXH32_SEED);
#endif
}

static bool validate_chunk(const metadata_t *chunk)
{
    if (!chunk || !is_within_heap(chunk))
    {
        return false;
    }
    return calculate_chunk_checksum(chunk) == chunk->checksum;
}

/* Chunk management functions */
static void create_free_chunk(metadata_t *chunk, size_t size, void *previous_chunk)
{
    chunk->chunk_size = size;
    chunk->prev_chunk = previous_chunk;
    chunk->is_allocated = false;
    chunk->current_alignment = calculate_alignment(chunk);
    chunk->checksum = calculate_chunk_checksum(chunk);
}

static metadata_t *find_chunk_for_pointer(void *ptr)
{
    if (!ptr || !is_within_heap(ptr))
    {
        return NULL;
    }

    metadata_t *metadata = (metadata_t *)((uint8_t *)ptr - sizeof(metadata_t));
    while ((uint8_t *)metadata >= HEAP_START)
    {
        if (validate_chunk(metadata) && metadata->is_allocated &&
            CHUNK_DATA(metadata) == ptr)
        {
            return metadata;
        }
        metadata = (metadata_t *)((uint8_t *)metadata - 1);
    }
    return NULL;
}

static bool try_coalesce_with_next(metadata_t *chunk)
{
    metadata_t *next = (metadata_t *)NEXT_CHUNK(chunk);
    if (is_within_heap(next) && validate_chunk(next) && !next->is_allocated)
    {
        chunk->chunk_size += sizeof(metadata_t) + next->chunk_size;
        chunk->checksum = calculate_chunk_checksum(chunk);
        return true;
    }
    return false;
}

static void *split_chunk_if_possible(metadata_t *chunk, size_t required_size)
{
    size_t remaining = chunk->chunk_size - required_size;
    if (remaining >= sizeof(metadata_t) + SPLIT_THRESHOLD)
    {
        metadata_t *split_chunk = (metadata_t *)((uint8_t *)chunk +
                                                 sizeof(metadata_t) + required_size);
        create_free_chunk(split_chunk, remaining - sizeof(metadata_t), chunk);
        chunk->chunk_size = required_size;
        chunk->checksum = calculate_chunk_checksum(chunk);
    }
    return CHUNK_DATA(chunk);
}

/* Public function implementations */
bool heap_init(void)
{
    if (is_initialized)
    {
        return true;
    }

    metadata_t *initial_metadata = (metadata_t *)heap;
    initial_metadata->chunk_size = HEAP_CAPACITY - sizeof(metadata_t);
    initial_metadata->prev_chunk = NULL;
    initial_metadata->is_allocated = false;
    initial_metadata->current_alignment = MAX_ALIGNMENT;
    initial_metadata->checksum = calculate_chunk_checksum(initial_metadata);

    if (DEBUG_LOGGING)
    {
        printf("Heap initialized:\n"
               "- Start address: %p\n"
               "- Total size: %d bytes\n"
               "- Metadata size: %zu bytes\n"
               "- Initial free chunk: %zu bytes\n",
               (void *)HEAP_START, HEAP_CAPACITY,
               sizeof(metadata_t), initial_metadata->chunk_size);
    }

    is_initialized = true;
    return true;
}

void *heap_alloc(size_t size, alignment_t alignment)
{
    if (size == 0 || size > HEAP_CAPACITY || !is_initialized)
    {
        return NULL;
    }

    if ((alignment & (alignment - 1)) != 0 || alignment > MAX_ALIGNMENT)
    {
        alignment = DEFAULT_ALIGNMENT;
    }

    metadata_t *current = (metadata_t *)HEAP_START;
    while (is_within_heap(current))
    {
        if (!validate_chunk(current))
        {
            if (DEBUG_LOGGING)
            {
                printf("Warning: Corrupted chunk detected at %p\n", (void *)current);
            }
            return NULL;
        }

        if (!current->is_allocated)
        {
            void *data_start = CHUNK_DATA(current);
            void *aligned_data;
            size_t padding, total_size;

            if (current->current_alignment >= alignment)
            {
                padding = 0;
                aligned_data = data_start;
            }
            else
            {
                aligned_data = align_ptr(data_start, alignment);
                padding = (uint8_t *)aligned_data - (uint8_t *)data_start;
            }

            total_size = size + padding;
            if (current->chunk_size >= total_size)
            {
                current->is_allocated = true;
                current->current_alignment = alignment;
                void *result = split_chunk_if_possible(current, total_size);
                current->checksum = calculate_chunk_checksum(current);

                if (DEBUG_LOGGING)
                {
                    printf("Allocated %zu bytes at %p (aligned to %d)\n",
                           size, result, alignment);
                }
                return result;
            }
        }
        current = (metadata_t *)NEXT_CHUNK(current);
    }

    if (DEBUG_LOGGING)
    {
        printf("Allocation failed: No suitable chunk found for %zu bytes\n", size);
    }
    return NULL;
}

void *heap_realloc(void *ptr, size_t new_size, alignment_t new_alignment)
{
    if (!ptr)
    {
        return heap_alloc(new_size, new_alignment);
    }

    if (new_size == 0)
    {
        heap_free(ptr);
        return NULL;
    }

    metadata_t *chunk = find_chunk_for_pointer(ptr);
    if (!chunk)
    {
        return NULL;
    }

    if (new_alignment > MAX_ALIGNMENT || (new_alignment & (new_alignment - 1)))
    {
        new_alignment = DEFAULT_ALIGNMENT;
    }

    // Try to shrink or expand in place
    if (new_size <= chunk->chunk_size && new_alignment <= chunk->current_alignment)
    {
        return split_chunk_if_possible(chunk, new_size);
    }

    // Try to expand using next chunk
    if (try_coalesce_with_next(chunk) && chunk->chunk_size >= new_size)
    {
        return split_chunk_if_possible(chunk, new_size);
    }

    // Allocate new chunk and copy data
    void *new_ptr = heap_alloc(new_size, new_alignment);
    if (!new_ptr)
    {
        return NULL;
    }

    memcpy(new_ptr, ptr, chunk->chunk_size < new_size ? chunk->chunk_size : new_size);
    heap_free(ptr);

    if (DEBUG_LOGGING)
    {
        printf("Realloc relocated: %p -> %p, new size: %zu\n",
               ptr, new_ptr, new_size);
    }
    return new_ptr;
}

void heap_free(void *ptr)
{
    if (!ptr || !is_initialized)
    {
        return;
    }

    metadata_t *chunk = find_chunk_for_pointer(ptr);
    if (!chunk)
    {
        if (DEBUG_LOGGING)
        {
            printf("Warning: Could not find valid metadata for pointer %p\n", ptr);
        }
        return;
    }

    chunk->is_allocated = false;
    chunk->current_alignment = calculate_alignment(chunk);
    chunk->checksum = calculate_chunk_checksum(chunk);

    if (DEBUG_LOGGING)
    {
        printf("Freed chunk at %p (size: %zu)\n", ptr, chunk->chunk_size);
    }

    try_coalesce_with_next(chunk);
}

void heap_get_stats(size_t *total_size, size_t *used_size,
                    size_t *free_size, size_t *largest_free_block)
{
    *total_size = HEAP_CAPACITY;
    *used_size = *free_size = *largest_free_block = 0;

    metadata_t *current = (metadata_t *)HEAP_START;
    while (is_within_heap(current))
    {
        if (!validate_chunk(current))
        {
            break;
        }

        if (current->is_allocated)
        {
            *used_size += current->chunk_size;
        }
        else
        {
            *free_size += current->chunk_size;
            *largest_free_block = current->chunk_size > *largest_free_block ? current->chunk_size : *largest_free_block;
        }
        current = (metadata_t *)NEXT_CHUNK(current);
    }
}

#endif // MEM_IMPLEMENTATION
#endif // HEAP_ALLOCATOR_H