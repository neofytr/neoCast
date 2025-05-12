#ifndef AB6C05AF_6E23_4B0A_89C2_DFB861401101
#define AB6C05AF_6E23_4B0A_89C2_DFB861401101

#include <stdlib.h>
#include <stdio.h>

/**
 * @brief Error codes for the strix string library
 *
 * Enumeration of all possible error conditions that can occur during strix operations.
 * These codes are set in the thread-local strix_errno variable when operations fail.
 */
typedef enum
{
    STRIX_SUCCESS = 0,              ///< Operation completed successfully
    STRIX_ERR_NULL_PTR,             ///< Null pointer passed as argument where non-null required
    STRIX_ERR_MALLOC_FAILED,        ///< Dynamic memory allocation operation failed
    STRIX_ERR_MEMCPY_FAILED,        ///< Memory copy operation failed
    STRIX_ERR_MEMMOVE_FAILED,       ///< Memory move operation failed
    STRIX_ERR_INVALID_LENGTH,       ///< Invalid string length specified or computed
    STRIX_ERR_EMPTY_STRING,         ///< Empty string provided where non-empty required
    STRIX_ERR_STRIX_STR_NULL,       ///< Null string in the strix structure provided
    STRIX_ERR_INVALID_POS,          ///< Invalid strix string position provided
    STRIX_ERR_OUT_OF_BOUNDS_ACCESS, ///< Out of bounds element access
    STRIX_ERR_INVALID_BOUNDS,       ///< Invalid bounds given for slicing
    STRIX_ERR_INVALID_DOUBLE,       ///< Invalid double value in the strix string
    STRIX_ERR_INVALID_INT,          ///< Invalid int value in the strix string
    STRIX_ERR_INT_OVERFLOW,         ///< Integer in the strix string overflows 8 bytes
    STRIX_ERR_INVALID_STRIDE,       ///< Invalid stride given
    STRIX_ERR_STDIO,                ///< Error from the stdio library while doing operations on the given file\nSee thread local errno for more information on the error
} strix_error_t;

/* _Thread_local has been supported since C11 */

/**
 * @brief Thread-local error state for strix operations
 *
 * This variable stores the error state of the most recent strix operation for the current thread.
 * It is automatically initialized to STRIX_SUCCESS and updated by strix functions when errors occur.
 * Each thread maintains its own independent error state.
 */
static _Thread_local strix_error_t strix_errno = STRIX_SUCCESS;

/**
 * @brief Array of human-readable error messages
 *
 * Contains descriptive messages corresponding to each error code in strix_error_t.
 * The index of each message matches its corresponding error code value.
 * Used by strix_perror to provide human-readable error descriptions.
 */
static const char *strix_error_messages[] = {
    "Success",
    "Null pointer argument",
    "Memory allocation failed",
    "Memory copy operation failed",
    "Memory move operation failed",
    "Invalid string length",
    "Empty string where not allowed",
    "Null string in the strix structure provided",
    "Invalid strix string position provided",
    "Out of bounds element access",
    "Invalid bounds given for slicing",
    "Invalid double value in the strix string",
    "Invalid int value in the strix string",
    "Integer in the strix string overflows 8 bytes",
    "Invalid stride given",
    "Error from the stdio library while doing operations on the given file\nSee thread local errno for more information on the error"};

/**
 * @brief Prints a formatted error message to stderr
 *
 * Outputs the provided prefix string followed by the error message corresponding
 * to the current value of strix_errno.
 *
 * @param prefix String to print before the error message (can be NULL)
 *
 * Example usage:
 * @code
 * if (!strix_some_function(s)) {
 *     strix_perror("Failed to process string");  // Prints: "Failed to process string: <error message>"
 * }
 * @endcode
 */
void strix_perror(const char *prefix);

/**
 * @brief Retrieves the current error code
 *
 * Returns the current value of strix_errno for the calling thread.
 *
 * @return Current error code from strix_error_t enum
 *
 * Example usage:
 * @code
 * if (strix_get_error() == STRIX_ERR_MALLOC_FAILED) {
 *     // Handle memory allocation failure
 * }
 * @endcode
 */
strix_error_t strix_get_error(void);

#endif /* AB6C05AF_6E23_4B0A_89C2_DFB861401101 */