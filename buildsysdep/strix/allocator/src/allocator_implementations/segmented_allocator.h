#ifndef D46AFE7A_7823_4C7A_A759_A5737B4A74D1
#define D46AFE7A_7823_4C7A_A759_A5737B4A74D1

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdio.h>

#define HEAP_CAPACITY (65536)
#define FREE_CAPACITY (1024)
#define ALLOC_CAPACITY (1024)

#define MAX_ALIGNMENT (ALIGN_64)
#define MAX_ALIGNMENT_INT (64)
#define DEFAULT_ALIGNMENT ((alignment_t)(sizeof(void *))) // by default align on pointer size, this is enough for most platforms and architectures

#define SPLIT_CUTOFF (16)

#define FREE_DEFRAG_CUTOFF (32) // must be a power of 2

#define BIN_8_SIZE (8)
#define BIN_16_SIZE (16)
#define BIN_32_SIZE (32)
#define BIN_8_CAPACITY (1024)
#define BIN_16_CAPACITY (512)
#define BIN_32_CAPACITY (256)

typedef enum
{
    ALLOC_TYPE_HEAP,
    ALLOC_TYPE_BIN_8,
    ALLOC_TYPE_BIN_16,
    ALLOC_TYPE_BIN_32
} allocation_type_t;

typedef enum
{
    ALIGN_1 = 1,
    ALIGN_2 = 2,
    ALIGN_4 = 4,
    ALIGN_8 = 8,
    ALIGN_16 = 16,
    ALIGN_32 = 32,
    ALIGN_64 = 64,
    ALIGN_MAX = ALIGN_64,
    ALIGN_DEFAULT = ALIGN_8,
    ALIGN_SAME = 0,
} alignment_t;

typedef struct
{
    void *chunk_ptr;
    void *data_ptr;
    void *prev_chunk_ptr;
    size_t size;
    size_t usable_size;
    alignment_t current_alignment;
    allocation_type_t alloc_type;
    bool mark;
} metadata_t;

static metadata_t free_array[FREE_CAPACITY] = {0};
static metadata_t alloc_array[ALLOC_CAPACITY] = {0};
static size_t free_array_size = 0;
static size_t alloc_array_size = 0;

static uint8_t heap[HEAP_CAPACITY] __attribute__((aligned(MAX_ALIGNMENT_INT))) = {0};

static uint8_t bin_8[BIN_8_CAPACITY * BIN_8_SIZE] __attribute__((aligned(MAX_ALIGNMENT_INT))) = {0};
static uint8_t bin_16[BIN_16_CAPACITY * BIN_16_SIZE] __attribute__((aligned(MAX_ALIGNMENT_INT))) = {0};
static uint8_t bin_32[BIN_32_CAPACITY * BIN_32_SIZE] __attribute__((aligned(MAX_ALIGNMENT_INT))) = {0};

static metadata_t free_bin_8[BIN_8_CAPACITY] = {0};
static metadata_t alloc_bin_8[BIN_8_CAPACITY] = {0};
static metadata_t free_bin_16[BIN_16_CAPACITY] = {0};
static metadata_t alloc_bin_16[BIN_16_CAPACITY] = {0};
static metadata_t free_bin_32[BIN_32_CAPACITY] = {0};
static metadata_t alloc_bin_32[BIN_32_CAPACITY] = {0};

static size_t free_bin_8_size = 0;
static size_t alloc_bin_8_size = 0;
static size_t free_bin_16_size = 0;
static size_t alloc_bin_16_size = 0;
static size_t free_bin_32_size = 0;
static size_t alloc_bin_32_size = 0;

static size_t num_of_free_called_on_heap = 0;

void *heap_alloc(size_t size, alignment_t alignment);
void heap_free(void *ptr);
void heap_init();
void *heap_realloc(void *ptr, size_t new_size, alignment_t new_alignment);

#ifdef MEM_IMPLEMENTATION

static void init_bins();
static int64_t search_by_ptr(void *ptr, metadata_t *array, size_t array_size);
static int64_t search_by_ptr_in_free_array(void *ptr);
static int64_t search_by_ptr_in_alloc_array(void *ptr);
static int64_t search_by_size_in_free_array(size_t size, alignment_t alignment);
static inline alignment_t calculate_alignment(const void *ptr);
static bool remove_from_array(size_t index, metadata_t *array, size_t *array_size);
static bool remove_from_free_array(size_t index);
static bool remove_from_alloc_array(size_t index);
static size_t find_insertion_position(void *data_ptr, metadata_t *array, size_t array_size);
static bool add_into_array(metadata_t chunk, metadata_t *array, size_t *array_size, size_t capacity);
static bool add_into_free_array(void *chunk_ptr, void *data_ptr, void *prev_chunk_ptr,
                                size_t size, size_t usable_size, alignment_t alignment);
static bool add_into_alloc_array(void *chunk_ptr, void *data_ptr, void *prev_chunk_ptr,
                                 size_t size, size_t usable_size, alignment_t alignment);
static void defragment_heap();

#ifdef GC_COLLECT

extern char __data_start, _edata; // data section boundaries
extern char __bss_start, _end;    // bss section boundaries

#define MAX_GC_ROOTS 1024
static void *gc_roots[MAX_GC_ROOTS];
static size_t gc_roots_count = 0;

void gc_register_root(void *root)
{
    if (gc_roots_count < MAX_GC_ROOTS)
    {
        gc_roots[gc_roots_count++] = root;
    }
}

static bool is_valid_heap_ptr(void *ptr)
{

    return ((uintptr_t)ptr >= (uintptr_t)heap && (uintptr_t)ptr < (uintptr_t)heap + HEAP_CAPACITY) ||
           ((uintptr_t)ptr >= (uintptr_t)bin_8 && (uintptr_t)ptr < (uintptr_t)bin_8 + BIN_8_CAPACITY * BIN_8_SIZE) ||
           ((uintptr_t)ptr >= (uintptr_t)bin_16 && (uintptr_t)ptr < (uintptr_t)bin_16 + BIN_16_CAPACITY * BIN_16_SIZE) ||
           ((uintptr_t)ptr >= (uintptr_t)bin_32 && (uintptr_t)ptr < (uintptr_t)bin_32 + BIN_32_CAPACITY * BIN_32_SIZE);
}

static bool is_marked_allocation(void *ptr)
{
    int64_t heap_index = search_by_ptr_in_alloc_array(ptr);
    if (heap_index != -1)
    {
        return alloc_array[heap_index].mark;
    }

    if ((uintptr_t)ptr >= (uintptr_t)bin_8 && (uintptr_t)ptr < (uintptr_t)bin_8 + BIN_8_CAPACITY * BIN_8_SIZE)
    {
        heap_index = search_by_ptr(ptr, alloc_bin_8, alloc_bin_8_size);
        return (heap_index != -1) ? alloc_bin_8[heap_index].mark : false;
    }
    if ((uintptr_t)ptr >= (uintptr_t)bin_16 && (uintptr_t)ptr < (uintptr_t)bin_16 + BIN_16_CAPACITY * BIN_16_SIZE)
    {
        heap_index = search_by_ptr(ptr, alloc_bin_16, alloc_bin_16_size);
        return (heap_index != -1) ? alloc_bin_16[heap_index].mark : false;
    }
    if ((uintptr_t)ptr >= (uintptr_t)bin_32 && (uintptr_t)ptr < (uintptr_t)bin_32 + BIN_32_CAPACITY * BIN_32_SIZE)
    {
        heap_index = search_by_ptr(ptr, alloc_bin_32, alloc_bin_32_size);
        return (heap_index != -1) ? alloc_bin_32[heap_index].mark : false;
    }

    return false;
}

static void mark_object(void *ptr)
{
    if (!ptr || !is_valid_heap_ptr(ptr) || is_marked_allocation(ptr))
    {
        return;
    }

    int64_t heap_index = search_by_ptr_in_alloc_array(ptr);
    metadata_t *metadata = NULL;

    if (heap_index != -1)
    {
        metadata = &alloc_array[heap_index];
    }
    else
    {
        if ((uintptr_t)ptr >= (uintptr_t)bin_8 && (uintptr_t)ptr < (uintptr_t)bin_8 + BIN_8_CAPACITY * BIN_8_SIZE)
        {
            heap_index = search_by_ptr(ptr, alloc_bin_8, alloc_bin_8_size);
            metadata = (heap_index != -1) ? &alloc_bin_8[heap_index] : NULL;
        }
        else if ((uintptr_t)ptr >= (uintptr_t)bin_16 && (uintptr_t)ptr < (uintptr_t)bin_16 + BIN_16_CAPACITY * BIN_16_SIZE)
        {
            heap_index = search_by_ptr(ptr, alloc_bin_16, alloc_bin_16_size);
            metadata = (heap_index != -1) ? &alloc_bin_16[heap_index] : NULL;
        }
        else if ((uintptr_t)ptr >= (uintptr_t)bin_32 && (uintptr_t)ptr < (uintptr_t)bin_32 + BIN_32_CAPACITY * BIN_32_SIZE)
        {
            heap_index = search_by_ptr(ptr, alloc_bin_32, alloc_bin_32_size);
            metadata = (heap_index != -1) ? &alloc_bin_32[heap_index] : NULL;
        }
    }

    if (!metadata)
        return;

    metadata->mark = true;

    for (size_t offset = 0; offset < metadata->usable_size; offset += sizeof(void *))
    {
        void *potential_ptr = *(void **)((char *)ptr + offset);
        mark_object(potential_ptr);
    }
}

static void mark_roots()
{
    for (size_t i = 0; i < gc_roots_count; i++)
    {
        mark_object(gc_roots[i]);
    }

    uintptr_t stack_bottom, stack_top;

#if defined(__linux__)
    void *stack_base;
    size_t stack_size;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_getstack(&attr, &stack_base, &stack_size);
    stack_bottom = (uintptr_t)stack_base;
    stack_top = stack_bottom + stack_size;
    pthread_attr_destroy(&attr);
#elif defined(__APPLE__)
    stack_bottom = (uintptr_t)pthread_get_stackaddr_np(pthread_self());
    stack_top = stack_bottom - pthread_get_stacksize_np(pthread_self());
#else
    uintptr_t sp;
    __asm__ __volatile__("mov %%rsp, %0" : "=r"(sp));
    stack_bottom = sp;
    stack_top = ;
#endif

    for (uintptr_t *ptr = (uintptr_t *)stack_bottom;
         ptr < (uintptr_t *)stack_top;
         ptr++)
    {
        mark_object((void *)*ptr);
    }

    for (void **ptr = (void **)&__data_start;
         ptr < (void **)&_edata;
         ptr++)
    {
        mark_object(*ptr);
    }

    for (void **ptr = (void **)&__bss_start;
         ptr < (void **)&_end;
         ptr++)
    {
        mark_object(*ptr);
    }
}

static void sweep()
{
    for (size_t i = 0; i < alloc_array_size; i++)
    {
        if (!alloc_array[i].mark)
        {
            heap_free(alloc_array[i].data_ptr);
            i--;
        }
        else
        {
            alloc_array[i].mark = false;
        }
    }

    void (*sweep_bin)(void *) = heap_free;

    for (size_t i = 0; i < alloc_bin_8_size; i++)
    {
        if (!alloc_bin_8[i].mark)
        {
            sweep_bin(alloc_bin_8[i].data_ptr);
            i--;
        }
        else
        {
            alloc_bin_8[i].mark = false;
        }
    }

    for (size_t i = 0; i < alloc_bin_16_size; i++)
    {
        if (!alloc_bin_16[i].mark)
        {
            sweep_bin(alloc_bin_16[i].data_ptr);
            i--;
        }
        else
        {
            alloc_bin_16[i].mark = false;
        }
    }

    for (size_t i = 0; i < alloc_bin_32_size; i++)
    {
        if (!alloc_bin_32[i].mark)
        {
            sweep_bin(alloc_bin_32[i].data_ptr);
            i--;
        }
        else
        {
            alloc_bin_32[i].mark = false;
        }
    }
}

void gc_collect()
{
    static bool collecting = false;
    if (collecting)
        return;
    collecting = true;

    mark_roots();

    sweep();

    collecting = false;
}

#endif // GC_COLLECT

static int64_t search_by_ptr(void *ptr, metadata_t *array, size_t array_size)
{
    size_t left = 0;
    size_t right = array_size;

    while (left < right)
    {
        size_t mid = (left + right) / 2;
        if (array[mid].data_ptr == ptr)
        {
            return mid;
        }
        if (array[mid].data_ptr < ptr)
        {
            left = mid + 1;
        }
        else
        {
            right = mid;
        }
    }
    return -1;
}

static int64_t search_by_ptr_in_free_array(void *ptr)
{
    return search_by_ptr(ptr, free_array, free_array_size);
}

static int64_t search_by_ptr_in_alloc_array(void *ptr)
{
    return search_by_ptr(ptr, alloc_array, alloc_array_size);
}

static int64_t search_by_size_in_free_array(size_t size, alignment_t alignment)
{
    size_t left = 0;
    size_t right = free_array_size;
    int64_t best_fit = -1;
    size_t smallest_sufficient_size = SIZE_MAX;

    while (left < right)
    {
        size_t mid = (left + right) / 2;
        metadata_t *current = &free_array[mid];

        size_t padding = ((alignment - (size_t)current->chunk_ptr) & (alignment - 1));
        size_t total_required = size + padding;

        if (current->size >= total_required)
        {
            if (current->size < smallest_sufficient_size)
            {
                smallest_sufficient_size = current->size;
                best_fit = mid;
            }
            right = mid;
        }
        else
        {
            left = mid + 1;
        }
    }

    return best_fit;
}

static inline alignment_t calculate_alignment(const void *ptr)
{
    uintptr_t addr = (uintptr_t)ptr;
    size_t alignment = ALIGN_1;

    while (alignment <= MAX_ALIGNMENT && !(addr & (alignment - 1)))
    {
        alignment = (alignment << 1);
    }

    return (alignment_t)(alignment >> 1);
}

static bool remove_from_array(size_t index, metadata_t *array, size_t *array_size)
{
    if (index >= *array_size)
    {
        return false;
    }

    memmove(&array[index], &array[index + 1],
            (*array_size - index - 1) * sizeof(metadata_t));
    (*array_size)--;
    return true;
}

static bool remove_from_free_array(size_t index)
{
    return remove_from_array(index, free_array, &free_array_size);
}

static bool remove_from_alloc_array(size_t index)
{
    return remove_from_array(index, alloc_array, &alloc_array_size);
}

static size_t find_insertion_position(void *data_ptr, metadata_t *array, size_t array_size)
{
    size_t left = 0;
    size_t right = array_size;

    while (left < right)
    {
        size_t mid = (left + right) / 2;
        if (array[mid].data_ptr <= data_ptr)
        {
            left = mid + 1;
        }
        else
        {
            right = mid;
        }
    }
    return left;
}

static bool add_into_array(metadata_t chunk, metadata_t *array, size_t *array_size, size_t capacity)
{
    if (*array_size >= capacity)
    {
        return false;
    }

    size_t pos = find_insertion_position(chunk.data_ptr, array, *array_size);

    if (pos < *array_size)
    {
        memmove(&array[pos + 1], &array[pos],
                (*array_size - pos) * sizeof(metadata_t));
    }

    array[pos] = chunk;
    (*array_size)++;
    return true;
}

static bool add_into_free_array(void *chunk_ptr, void *data_ptr, void *prev_chunk_ptr,
                                size_t size, size_t usable_size, alignment_t alignment)
{
    metadata_t chunk = {
        .chunk_ptr = chunk_ptr,
        .data_ptr = data_ptr,
        .prev_chunk_ptr = prev_chunk_ptr,
        .size = size,
        .usable_size = usable_size,
        .current_alignment = alignment};
    return add_into_array(chunk, free_array, &free_array_size, FREE_CAPACITY);
}

static bool add_into_alloc_array(void *chunk_ptr, void *data_ptr, void *prev_chunk_ptr,
                                 size_t size, size_t usable_size, alignment_t alignment)
{
    metadata_t chunk = {
        .chunk_ptr = chunk_ptr,
        .data_ptr = data_ptr,
        .prev_chunk_ptr = prev_chunk_ptr,
        .size = size,
        .usable_size = usable_size,
        .current_alignment = alignment};
    return add_into_array(chunk, alloc_array, &alloc_array_size, ALLOC_CAPACITY);
}

static void defragment_heap()
{
    bool defragmented;
    do
    {
        defragmented = false;
        for (size_t i = 0; i < free_array_size; i++)
        {
            metadata_t *current = &free_array[i];

            void *next_chunk = (uint8_t *)current->chunk_ptr + current->size;
            for (size_t j = 0; j < free_array_size; j++)
            {
                if (i != j && free_array[j].chunk_ptr == next_chunk)
                {
                    current->size += free_array[j].size;
                    remove_from_free_array(j);
                    defragmented = true;
                    break;
                }
            }

            int64_t prev_idx = search_by_ptr_in_free_array(current->prev_chunk_ptr);
            if (prev_idx >= 0)
            {
                metadata_t *prev = &free_array[prev_idx];
                prev->size += current->size;
                remove_from_free_array(i);
                defragmented = true;
                break;
            }
        }
    } while (defragmented);
}

void heap_init()
{
    static bool has_run = false;
    if (has_run)
    {
        return;
    }

    has_run = true;
    free_array_size = 0;
    alloc_array_size = 0;

    add_into_free_array(heap, heap, NULL, HEAP_CAPACITY, HEAP_CAPACITY, MAX_ALIGNMENT);
    free_array[0].alloc_type = ALLOC_TYPE_HEAP;

    init_bins();
}

void *heap_alloc(size_t size, alignment_t alignment)
{
    if (!size)
    {
        return NULL;
    }

    heap_init();

    if (((alignment) & (alignment - 1)) || (alignment > MAX_ALIGNMENT))
    {
        alignment = DEFAULT_ALIGNMENT;
    }

    metadata_t *target_free_array;
    metadata_t *target_alloc_array;
    size_t *target_free_size;
    size_t *target_alloc_size;
    size_t target_capacity;
    allocation_type_t alloc_type;

    if (size <= BIN_8_SIZE)
    {
        target_free_array = free_bin_8;
        target_alloc_array = alloc_bin_8;
        target_free_size = &free_bin_8_size;
        target_alloc_size = &alloc_bin_8_size;
        target_capacity = BIN_8_CAPACITY;
        size = BIN_8_SIZE;
        alloc_type = ALLOC_TYPE_BIN_8;
    }
    else if (size <= BIN_16_SIZE)
    {
        target_free_array = free_bin_16;
        target_alloc_array = alloc_bin_16;
        target_free_size = &free_bin_16_size;
        target_alloc_size = &alloc_bin_16_size;
        target_capacity = BIN_16_CAPACITY;
        size = BIN_16_SIZE;
        alloc_type = ALLOC_TYPE_BIN_16;
    }
    else if (size <= BIN_32_SIZE)
    {
        target_free_array = free_bin_32;
        target_alloc_array = alloc_bin_32;
        target_free_size = &free_bin_32_size;
        target_alloc_size = &alloc_bin_32_size;
        target_capacity = BIN_32_CAPACITY;
        size = BIN_32_SIZE;
        alloc_type = ALLOC_TYPE_BIN_32;
    }
    else
    {
        int64_t best_fit_index = search_by_size_in_free_array(size, alignment);
        if (best_fit_index < 0)
        {
            return NULL;
        }

        metadata_t *chunk = &free_array[best_fit_index];
        size_t padding = ((alignment - (size_t)chunk->chunk_ptr) & (alignment - 1));
        void *data_ptr = (uint8_t *)chunk->chunk_ptr + padding;

        if (padding >= SPLIT_CUTOFF)
        {
            add_into_free_array(chunk->chunk_ptr, chunk->chunk_ptr,
                                chunk->prev_chunk_ptr, padding, padding,
                                calculate_alignment(chunk->chunk_ptr));
            free_array[free_array_size - 1].alloc_type = ALLOC_TYPE_HEAP;

            chunk->chunk_ptr = (uint8_t *)chunk->chunk_ptr + padding;
            chunk->size -= padding;
            chunk->prev_chunk_ptr = (uint8_t *)chunk->chunk_ptr - padding;
        }

        size_t remaining = chunk->size - size;
        if (remaining >= SPLIT_CUTOFF)
        {
            void *new_chunk_ptr = (uint8_t *)chunk->chunk_ptr + size;
            add_into_free_array(new_chunk_ptr, new_chunk_ptr,
                                chunk->chunk_ptr, remaining, remaining,
                                calculate_alignment(new_chunk_ptr));
            free_array[free_array_size - 1].alloc_type = ALLOC_TYPE_HEAP;
            chunk->size = size;
        }

        add_into_alloc_array(chunk->chunk_ptr, data_ptr,
                             chunk->prev_chunk_ptr, chunk->size,
                             chunk->size - padding, alignment);
        alloc_array[alloc_array_size - 1].alloc_type = ALLOC_TYPE_HEAP;
        remove_from_free_array(best_fit_index);

        return data_ptr;
    }

    if (*target_free_size == 0)
    {
        return NULL;
    }

    metadata_t chunk = target_free_array[0];

    size_t padding = ((alignment - (size_t)chunk.chunk_ptr) & (alignment - 1));
    void *data_ptr = (uint8_t *)chunk.chunk_ptr + padding;

    size_t aligned_size = size;
    if (alignment < size)
    {
        aligned_size = ((size + (size - 1)) / size) * size;
    }

    uint8_t *bin_start;
    uint8_t *bin_end;
    switch (alloc_type)
    {
    case ALLOC_TYPE_BIN_8:
        bin_start = bin_8;
        bin_end = bin_8 + (BIN_8_CAPACITY * BIN_8_SIZE);
        break;
    case ALLOC_TYPE_BIN_16:
        bin_start = bin_16;
        bin_end = bin_16 + (BIN_16_CAPACITY * BIN_16_SIZE);
        break;
    case ALLOC_TYPE_BIN_32:
        bin_start = bin_32;
        bin_end = bin_32 + (BIN_32_CAPACITY * BIN_32_SIZE);
        break;
    default:
        return NULL;
    }

    if ((uint8_t *)data_ptr + aligned_size > bin_end || (uint8_t *)data_ptr < bin_start)
    {
        return NULL;
    }

    metadata_t alloc_chunk = {
        .chunk_ptr = chunk.chunk_ptr,
        .data_ptr = data_ptr,
        .prev_chunk_ptr = chunk.prev_chunk_ptr,
        .size = aligned_size,
        .usable_size = aligned_size - padding,
        .current_alignment = alignment,
        .alloc_type = alloc_type};

    if (!add_into_array(alloc_chunk, target_alloc_array, target_alloc_size, target_capacity))
    {
        return NULL;
    }

    remove_from_array(0, target_free_array, target_free_size);

    return data_ptr;
}

static void init_bins()
{
    static bool has_run = false;
    if (has_run)
    {
        return;
    }

    has_run = true;

    free_bin_8_size = 0;
    for (size_t i = 0; i < BIN_8_CAPACITY; i++)
    {
        void *chunk_ptr = &bin_8[i * BIN_8_SIZE];
        metadata_t chunk = {
            .chunk_ptr = chunk_ptr,
            .data_ptr = chunk_ptr,
            .prev_chunk_ptr = i > 0 ? &bin_8[(i - 1) * BIN_8_SIZE] : NULL,
            .size = BIN_8_SIZE,
            .usable_size = BIN_8_SIZE,
            .current_alignment = MAX_ALIGNMENT,
            .alloc_type = ALLOC_TYPE_BIN_8};
        add_into_array(chunk, free_bin_8, &free_bin_8_size, BIN_8_CAPACITY);
    }

    free_bin_16_size = 0;
    for (size_t i = 0; i < BIN_16_CAPACITY; i++)
    {
        void *chunk_ptr = &bin_16[i * BIN_16_SIZE];
        metadata_t chunk = {
            .chunk_ptr = chunk_ptr,
            .data_ptr = chunk_ptr,
            .prev_chunk_ptr = i > 0 ? &bin_16[(i - 1) * BIN_16_SIZE] : NULL,
            .size = BIN_16_SIZE,
            .usable_size = BIN_16_SIZE,
            .current_alignment = MAX_ALIGNMENT,
            .alloc_type = ALLOC_TYPE_BIN_16};
        add_into_array(chunk, free_bin_16, &free_bin_16_size, BIN_16_CAPACITY);
    }

    free_bin_32_size = 0;
    for (size_t i = 0; i < BIN_32_CAPACITY; i++)
    {
        void *chunk_ptr = &bin_32[i * BIN_32_SIZE];
        metadata_t chunk = {
            .chunk_ptr = chunk_ptr,
            .data_ptr = chunk_ptr,
            .prev_chunk_ptr = i > 0 ? &bin_32[(i - 1) * BIN_32_SIZE] : NULL,
            .size = BIN_32_SIZE,
            .usable_size = BIN_32_SIZE,
            .current_alignment = MAX_ALIGNMENT,
            .alloc_type = ALLOC_TYPE_BIN_32};
        add_into_array(chunk, free_bin_32, &free_bin_32_size, BIN_32_CAPACITY);
    }
}

void heap_free(void *ptr)
{
    if (!ptr)
    {
        return;
    }

    metadata_t *chunk = NULL;
    metadata_t *source_alloc_array = NULL;
    metadata_t *target_free_array = NULL;
    size_t *source_alloc_size = NULL;
    size_t *target_free_size = NULL;
    size_t target_capacity = 0;
    int64_t alloc_index = -1;

    uintptr_t heap_start = (uintptr_t)heap;
    uintptr_t heap_end = heap_start + HEAP_CAPACITY;
    uintptr_t bin_8_start = (uintptr_t)bin_8;
    uintptr_t bin_8_end = bin_8_start + BIN_8_CAPACITY * BIN_8_SIZE;
    uintptr_t bin_16_start = (uintptr_t)bin_16;
    uintptr_t bin_16_end = (uintptr_t)bin_16 + BIN_16_CAPACITY * BIN_16_SIZE;
    uintptr_t bin_32_start = (uintptr_t)bin_32;
    uintptr_t bin_32_end = bin_32_start + BIN_32_SIZE * BIN_32_CAPACITY;

    if ((uintptr_t)ptr >= bin_8_start && (uintptr_t)ptr < bin_8_end)
    {
        source_alloc_array = alloc_bin_8;
        target_free_array = free_bin_8;
        source_alloc_size = &alloc_bin_8_size;
        target_free_size = &free_bin_8_size;
        target_capacity = BIN_8_CAPACITY;
        alloc_index = search_by_ptr(ptr, alloc_bin_8, alloc_bin_8_size);
    }
    else if ((uintptr_t)ptr >= bin_16_start && (uintptr_t)ptr < bin_16_end)
    {
        source_alloc_array = alloc_bin_16;
        target_free_array = free_bin_16;
        source_alloc_size = &alloc_bin_16_size;
        target_free_size = &free_bin_16_size;
        target_capacity = BIN_16_CAPACITY;
        alloc_index = search_by_ptr(ptr, alloc_bin_16, alloc_bin_16_size);
    }
    else if ((uintptr_t)ptr >= bin_32_start && (uintptr_t)ptr < bin_32_end)
    {
        source_alloc_array = alloc_bin_32;
        target_free_array = free_bin_32;
        source_alloc_size = &alloc_bin_32_size;
        target_free_size = &free_bin_32_size;
        target_capacity = BIN_32_CAPACITY;
        alloc_index = search_by_ptr(ptr, alloc_bin_32, alloc_bin_32_size);
    }
    else if ((uintptr_t)ptr >= heap_start && (uintptr_t)ptr < heap_end)
    {
        alloc_index = search_by_ptr_in_alloc_array(ptr);
    }
    else
    {
        return;
    }

    if (source_alloc_array && alloc_index >= 0)
    {
        chunk = &source_alloc_array[alloc_index];
        metadata_t free_chunk = {
            .chunk_ptr = chunk->chunk_ptr,
            .data_ptr = chunk->data_ptr,
            .prev_chunk_ptr = chunk->prev_chunk_ptr,
            .size = chunk->size,
            .usable_size = chunk->usable_size,
            .current_alignment = chunk->current_alignment,
            .alloc_type = chunk->alloc_type};

        if (!add_into_array(free_chunk, target_free_array, target_free_size, target_capacity))
        {
            return;
        }
        remove_from_array(alloc_index, source_alloc_array, source_alloc_size);
        return;
    }

    if (alloc_index >= 0)
    {
        chunk = &alloc_array[alloc_index];
        add_into_free_array(
            chunk->chunk_ptr,
            chunk->data_ptr,
            chunk->prev_chunk_ptr,
            chunk->size,
            chunk->usable_size,
            chunk->current_alignment);
        free_array[free_array_size - 1].alloc_type = ALLOC_TYPE_HEAP;
        remove_from_alloc_array(alloc_index);
        if (!num_of_free_called_on_heap && (FREE_DEFRAG_CUTOFF - 1))
        {
            defragment_heap();
        }
    }
}

void *heap_realloc(void *ptr, size_t new_size, alignment_t new_alignment)
{
    if (!ptr)
    {
        return heap_alloc(new_size, new_alignment);
    }

    if (!new_size)
    {
        heap_free(ptr);
        return NULL;
    }

    if (((new_alignment) & (new_alignment - 1)) || (new_alignment > MAX_ALIGNMENT))
    {
        new_alignment = DEFAULT_ALIGNMENT;
    }

    int64_t ptr_index = search_by_ptr_in_alloc_array(ptr);
    if (ptr_index < 0)
    {
        return NULL;
    }

    metadata_t *chunk = &alloc_array[ptr_index];

    if (new_size <= chunk->size)
    {
        if (new_alignment != chunk->current_alignment)
        {
            void *new_ptr = heap_alloc(new_size, new_alignment);
            if (!new_ptr)
            {
                return NULL;
            }

            size_t copy_size = new_size < chunk->usable_size ? new_size : chunk->usable_size;
            memcpy(new_ptr, ptr, copy_size);
            heap_free(ptr);
            return new_ptr;
        }

        // now if the alignment is same and the size is below
        size_t remaining = chunk->size - new_size;

        // only split if remaining space is above cutoff
        if (remaining >= SPLIT_CUTOFF)
        {
            void *new_chunk_ptr = (uint8_t *)chunk->chunk_ptr + new_size;
            add_into_free_array(new_chunk_ptr, new_chunk_ptr,
                                chunk->chunk_ptr, remaining, remaining,
                                calculate_alignment(new_chunk_ptr));
            chunk->size = new_size;
        }

        return ptr;
    }

    void *new_ptr = heap_alloc(new_size, new_alignment);
    if (!new_ptr)
    {
        return NULL;
    }

    memcpy(new_ptr, ptr, chunk->usable_size);
    heap_free(ptr);
    return new_ptr;
}

#endif // MEM_IMPLEMENTATION

#undef HEAP_CAPACITY
#undef FREE_CAPACITY
#undef ALLOC_CAPACITY

#undef MAX_ALIGNMENT
#undef MAX_ALIGNMENT_INT
#undef DEFAULT_ALIGNMENT // by default align on pointer size, this is enough for most platforms and architectures

#undef SPLIT_CUTOFF

#undef FREE_DEFRAG_CUTOFF // must be a power of 2

#undef BIN_8_SIZE
#undef BIN_16_SIZE
#undef BIN_32_SIZE
#undef BIN_8_CAPACITY
#undef BIN_16_CAPACITY
#undef BIN_32_CAPACITY

#endif /* D46AFE7A_7823_4C7A_A759_A5737B4A74D1 */
