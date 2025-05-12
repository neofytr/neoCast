#ifndef A4921AE8_DB77_42E3_A83E_9D3D0C69BDE0
#define A4921AE8_DB77_42E3_A83E_9D3D0C69BDE0

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include "string_search.h"
#include <stdbool.h>

/**
 * @brief String handling structure that stores both the string and its length
 *
 * This structure provides a way to handle strings with explicit length tracking,
 * avoiding the need for null-termination and allowing for binary data.
 */
typedef struct
{
    char *str;  // Pointer to the string data
    size_t len; // Length of the string
} strix_t;

typedef struct
{
    strix_t **strix_arr;
    size_t len;
} strix_arr_t;

#define MAX_SUBSTRIX_NUM 2048

/**
 * @brief Format macro for printf-style functions
 *
 * Used to print strix_t strings with proper length handling.
 * Example: printf(STRIX_FORMAT, STRIX_PRINT(my_strix));
 */
#define STRIX_FORMAT "%.*s"

/**
 * @brief Print macro for strix_t structures
 *
 * Expands to the length and string pointer needed by STRIX_FORMAT.
 * Must be used in conjunction with STRIX_FORMAT.
 */
#define STRIX_PRINT(string) (int)(string)->len, (string)->str

/**
 * @brief Creates a new strix_t structure from a C-style string
 *
 * @param str Input string to copy (must be null-terminated)
 * @return strix_t* Pointer to new strix_t structure, or NULL on failure
 *
 * Edge cases:
 * - Returns NULL if input string is NULL
 * - Returns NULL if memory allocation fails for strix_t
 * - Returns NULL if memory allocation fails for internal string
 * - Returns NULL if string copy fails
 */
strix_t *strix_create(const char *str);

/**
 * @brief Creates a deep copy of an existing strix_t structure
 *
 * @param strix Source strix_t to duplicate
 * @return strix_t* Pointer to new strix_t structure, or NULL on failure
 *
 * Edge cases:
 * - Returns NULL if input strix is NULL
 * - Returns NULL if input strix has length 0
 * - Returns NULL if memory allocation fails for new strix_t
 * - Returns NULL if memory allocation fails for internal string
 * - Returns NULL if string copy fails
 */
strix_t *strix_duplicate(const strix_t *strix);

/**
 * @brief Modifies an existing strix_t structure with a new string
 *
 * Frees the existing string and replaces it with a new one.
 *
 * @param strix Target strix_t to modify
 * @param str New string to copy into the structure
 * @return bool true on success, false on failure
 *
 * Edge cases:
 * - Returns false if input strix is NULL
 * - Returns false if input string is NULL
 */
bool strix_modify(strix_t *strix, const char *str);

/**
 * @brief Clears the contents of a strix_t structure
 *
 * Sets length to 0 and frees the internal string.
 *
 * @param strix strix_t structure to clear
 * @return bool true on success, false on failure
 *
 * Edge cases:
 * - Returns false if input strix is NULL
 */
bool strix_clear(strix_t *strix);

/**
 * @brief Concatenates two strix_t structures, modifying the first one
 *
 * Modifies the first strix_t by appending the contents of the second strix_t.
 *
 * @param strix_dest Target strix_t to modify
 * @param strix_src Source strix_t to append
 * @return bool true on success, false on failure
 *
 * Edge cases:
 * - Returns false if either input is NULL
 * - Returns false if memory reallocation fails
 * - Returns false if string copy fails
 */
bool strix_concat(strix_t *strix_dest, const strix_t *strix_src);
/**
 * @brief Appends a C-style string to an existing strix_t structure
 *
 * @param strix Target strix_t structure to modify
 * @param str String to append
 * @return bool true on success, false on failure
 *
 * Edge cases:
 * - Returns false if input strix is NULL
 * - Returns false if input string is NULL
 * - Returns false if append operation fails
 */
bool strix_append(strix_t *strix, const char *str);

/**
 * @brief Inserts the source strix_t structure's string to the destination strix_t structure's string at position pos
 *
 * @param strix_dest Target strix_t structure whose string is being appended to
 * @param strix_src strix_t structure whose string is being appended
 * @return bool true on success, false on failure
 *
 * Edge cases:
 * - Returns false if input strixs are NULL
 * - Returns false if input strix's strings are NULL
 * - Returns false if the destination strix length is less than or equal to pos
 */
bool strix_insert(strix_t *strix_dest, strix_t *strix_src, size_t pos);

/**
 * @brief Appends a substring at a specified position in a strix_t structure
 *
 * @param strix Target strix_t structure to modify
 * @param pos Position at which to insert the substring
 * @param substr String to insert
 * @return bool true on success, false on failure
 *
 * Edge cases:
 * - Returns false if input strix is NULL
 * - Returns false if input substring is NULL
 * - Returns false if pos is greater than strix length
 * - Returns false if memory reallocation fails
 */
bool strix_insert_str(strix_t *strix, size_t pos, const char *substr);

/**
 * @brief Erases a portion of the string starting from a specified position
 *
 * @param strix Target strix_t structure to modify
 * @param len Number of characters to erase
 * @param pos Starting position for erasure
 * @return bool true on success, false on failure
 *
 * Edge cases:
 * - Returns false if input strix is NULL
 * - Returns false if pos is greater than string length
 * - If len exceeds remaining string length, truncates to end of string
 */
bool strix_erase(strix_t *strix, size_t len, size_t pos);

/**
 * @brief Retrieves character at specified index in strix_t structure
 *
 * @param strix Source strix_t structure
 * @param index Position of character to retrieve
 * @return char Character at specified index, '\0' on error
 *
 * Edge cases:
 * - Returns '\0' if input strix is NULL
 * - Returns '\0' if index is out of bounds
 */
char strix_at(const strix_t *strix, size_t index);

/**
 * @brief Compares two strix_t structures for equality
 *
 * @param strix_one First strix_t structure to compare
 * @param strix_two Second strix_t structure to compare
 * @return int -1 on error, 0 if equal, 1 if unequal
 *
 * Edge cases:
 * - Returns -1 if either input is NULL
 * - Returns 1 if lengths differ
 */
int strix_equal(const strix_t *strix_one, const strix_t *strix_two);

/**
 * @brief Finds first occurrence of substring in strix_t structure
 *
 * @param strix Source strix_t structure to search in
 * @param substr Substring to search for
 * @return int64_t Index of first match, -1 on error, -2 if not found
 *
 * Edge cases:
 * - Returns -1 if either input is NULL
 * - Returns -2 if substring not found
 */
int64_t strix_find(const strix_t *strix, const char *substr);

/**
 * @brief Finds all occurrences of substring in strix_t structure
 *
 * @param strix Source strix_t structure to search in
 * @param substr Substring to search for
 * @return position_t* Structure containing all match positions, NULL on error
 *
 * Edge cases:
 * - Returns NULL if either input is NULL
 * - Returns position_t with len = -2 if substring not found
 * - Returns NULL if memory allocation fails
 */
position_t *strix_find_all(const strix_t *strix, const char *substr);

/**
 * @brief Frees memory allocated for position_t structure
 *
 * @param position Position structure to free
 */
void strix_position_free(position_t *position);

/**
 * @brief Finds first occurrence of one strix_t within another
 *
 * @param strix_one Source strix_t structure to search in
 * @param strix_two Strix_t structure to search for
 * @return int64_t Index of first match, -1 on error, -2 if not found
 *
 * Edge cases:
 * - Returns -1 if either input is NULL
 * - Returns -2 if substring not found
 */
int64_t strix_find_subtrix(const strix_t *strix_one, const strix_t *strix_two);

/**
 * @brief Finds all occurrences of one strix_t within another
 *
 * @param strix_one Source strix_t structure to search in
 * @param strix_two Strix_t structure to search for
 * @return position_t* Structure containing all match positions, NULL on error
 *
 * Edge cases:
 * - Returns NULL if either input is NULL
 * - Returns position_t with len = -2 if not found
 * - Returns NULL if memory allocation fails
 */
position_t *strix_find_subtrix_all(const strix_t *strix_one, const strix_t *strix_two);

/**
 * @brief Splits a strix_t into array of strix_t structures by delimiter
 *
 * @param strix Source strix_t structure to split
 * @param delim Delimiter character
 * @return strix_arr_t* Array of resulting strix_t structures, NULL on error
 *
 * Edge cases:
 * - Returns NULL if input strix is NULL
 * - Returns NULL if memory allocation fails
 * - Limited to MAX_SUBSTRIX_NUM (2048) splits
 */
strix_arr_t *strix_split_by_delim(const strix_t *strix, const char delim);

/**
 * @brief Frees memory allocated for strix_arr_t structure
 *
 * @param strix_arr Array structure to free
 */
void strix_free_strix_arr(strix_arr_t *strix_arr);

/**
 * @brief Splits a strix_t into array of strix_t structures by substring
 *
 * @param strix Source strix_t structure to split
 * @param substr Substring to split on
 * @return strix_arr_t* Array of resulting strix_t structures, NULL on error
 *
 * Edge cases:
 * - Returns NULL if either input is NULL
 * - Returns NULL if memory allocation fails
 * - Limited to MAX_SUBSTRIX_NUM (2048) splits
 */
strix_arr_t *strix_split_by_substr(const strix_t *strix, const char *substr);

/**
 * @brief Splits a strix_t into array of strix_t structures by another strix_t
 *
 * @param strix Source strix_t structure to split
 * @param substrix Strix_t structure to split on
 * @return strix_arr_t* Array of resulting strix_t structures, NULL on error
 *
 * Edge cases:
 * - Returns NULL if either input is NULL
 * - Returns NULL if memory allocation fails
 * - Limited to MAX_SUBSTRIX_NUM (2048) splits
 */
strix_arr_t *strix_split_by_substrix(const strix_t *strix, const strix_t *substrix);

/**
 * @brief Creates a new strix_t containing a subset of another strix_t
 *
 * @param strix Source strix_t structure
 * @param start Starting index of slice
 * @param end Ending index of slice (exclusive)
 * @return strix_t* New strix_t containing the slice, NULL on error
 *
 * Edge cases:
 * - Returns NULL if input strix is NULL
 * - Returns NULL if start is greater than end
 * - Returns NULL if end is greater than strix length
 * - Returns NULL if memory allocation fails
 */
strix_t *strix_slice(const strix_t *strix, size_t start, size_t end);

/**
 * @brief Joins an array of strix_t structures using a delimiter
 *
 * @param strix_arr Array of strix_t structures to join
 * @param len Length of array
 * @param delim Delimiter character
 * @return strix_t* New strix_t containing joined string, NULL on error
 *
 * Edge cases:
 * - Returns NULL if input array is NULL
 * - Returns NULL if len is 0
 * - Returns NULL if memory allocation fails
 */
strix_t *strix_join_via_delim(const strix_t **strix_arr, size_t len, const char delim);

/**
 * @brief Joins an array of strix_t structures using a substring
 *
 * @param strix_arr Array of strix_t structures to join
 * @param len Length of array
 * @param substr Substring to use as separator
 * @return strix_t* New strix_t containing joined string, NULL on error
 *
 * Edge cases:
 * - Returns NULL if input array or substr is NULL
 * - Returns NULL if len is 0
 * - Returns NULL if memory allocation fails
 */
strix_t *strix_join_via_substr(const strix_t **strix_arr, size_t len, const char *substr);

/**
 * @brief Joins an array of strix_t structures using another strix_t
 *
 * @param strix_arr Array of strix_t structures to join
 * @param len Length of array
 * @param substrix Strix_t structure to use as separator
 * @return strix_t* New strix_t containing joined string, NULL on error
 *
 * Edge cases:
 * - Returns NULL if input array or substrix is NULL
 * - Returns NULL if len is 0
 * - Returns NULL if memory allocation fails
 */
strix_t *strix_join_via_substrix(const strix_t **strix_arr, size_t len, const strix_t *substrix);

/**
 * @brief Frees memory allocated for strix_t structure
 *
 * @param string Strix_t structure to free
 */
void strix_free(strix_t *string);

/**
 * @brief Removes whitespace from both ends of a strix_t in place
 *
 * Trims leading and trailing whitespace from the provided strix_t.
 * The operation modifies the original strix structure directly.
 *
 * @param strix Pointer to the strix_t structure to trim
 * @return bool True on success, false on failure
 *
 * Edge cases:
 * - Returns false if input strix is NULL (sets STRIX_ERR_NULL_PTR)
 * - Returns false if strix->str is NULL (sets STRIX_ERR_STRIX_STR_NULL)
 * - Does nothing if the strix is already empty
 * - Frees the original string if it contains only whitespace
 * - Returns false if memory allocation fails (sets STRIX_ERR_MALLOC_FAILED)
 * - Returns false if memcpy fails (sets STRIX_ERR_MEMCPY_FAILED)
 */
bool strix_trim_whitespace(strix_t *strix);

/**
 * @brief Removes a specified character from both ends of a strix_t in place
 *
 * Trims leading and trailing occurrences of the specified character from
 * the provided strix_t. The operation modifies the original strix structure directly.
 *
 * @param strix Pointer to the strix_t structure to trim
 * @param trim Character to remove from both ends
 * @return bool True on success, false on failure
 *
 * Edge cases:
 * - Returns false if input strix is NULL (sets STRIX_ERR_NULL_PTR)
 * - Returns false if strix->str is NULL (sets STRIX_ERR_STRIX_STR_NULL)
 * - Does nothing if the strix is already empty
 * - Frees the original string if it contains only the trim character
 * - Returns false if memory allocation fails (sets STRIX_ERR_MALLOC_FAILED)
 * - Returns false if memcpy fails (sets STRIX_ERR_MEMCPY_FAILED)
 */
bool strix_trim_char(strix_t *strix, const char trim);

/**
 * @brief Converts a strix_t to a double value
 *
 * This function converts the string in the provided strix_t structure to a double value.
 * The function handles optional signs ('+' and '-') and a decimal point for fractional numbers.
 * It stores the result in a double and returns it.
 *
 * @param strix Pointer to the strix_t structure to convert
 * @return double The converted double value, or -1 if there is an error (error detected through strix_errno)
 *
 * Errors:
 * - Sets strix_errno to STRIX_ERR_INVALID_DOUBLE if the string is not a valid number
 * - Returns -1 if an invalid character, multiple decimal points, or improper sign usage is detected
 * - strix_errno must be checked for detailed error information
 */
double strix_to_double(strix_t *strix);

/**
 * @brief Converts a strix_t to a signed integer
 *
 * This function converts the string in the provided strix_t structure to a signed 64-bit integer.
 * The function handles optional signs ('+' and '-') and performs overflow checks before conversion.
 * It returns the converted integer if successful or 0 in case of failure.
 *
 * @param strix Pointer to the strix_t structure to convert
 * @return int64_t The converted signed integer, or 0 if there is an error (error detected through strix_errno)
 *
 * Errors:
 * - Sets strix_errno to STRIX_ERR_INVALID_DOUBLE if the string is not a valid signed integer
 * - Returns 0 if the string contains invalid characters, or the integer overflows
 * - strix_errno must be checked for detailed error information
 */
int64_t strix_to_signed_int(strix_t *strix);

/**
 * @brief Converts a strix_t to an unsigned integer
 *
 * This function converts the string in the provided strix_t structure to an unsigned 64-bit integer.
 * It handles an optional positive sign ('+'), and performs overflow checks before conversion.
 * It returns the converted integer if successful or 0 in case of failure.
 *
 * @param strix Pointer to the strix_t structure to convert
 * @return uint64_t The converted unsigned integer, or 0 if there is an error (error detected through strix_errno)
 *
 * Errors:
 * - Sets strix_errno to STRIX_ERR_INVALID_DOUBLE if the string is not a valid unsigned integer
 * - Returns 0 if the string contains invalid characters, or the integer overflows
 * - strix_errno must be checked for detailed error information
 */
uint64_t strix_to_unsigned_int(strix_t *strix);

/**
 * @brief Counts the occurrences of a specific character in a strix_t
 *
 * This function counts how many times the specified character appears in the string contained in the given strix_t structure.
 * It returns the count of occurrences, or -1 in case of an error.
 *
 * @param strix Pointer to the strix_t structure to analyze
 * @param chr The character to count within the strix_t string
 * @return int64_t The count of the specified character, or -1 if there is an error
 *
 * Errors:
 * - Returns -1 if the strix_t pointer is NULL or the string is invalid
 * - Additional error information should be handled externally
 */
int64_t strix_count_char(const strix_t *strix, const char chr);

/**
 * @brief Counts the occurrences of a specific substring in a strix_t
 *
 * This function counts how many times the specified substring appears within the string of the given strix_t structure.
 * It returns the count of occurrences, or -1 in case of an error.
 *
 * @param strix Pointer to the strix_t structure to analyze
 * @param substr Pointer to the null-terminated string representing the substring to count
 * @return int64_t The count of the specified substring, or -1 if there is an error
 *
 * Errors:
 * - Returns -1 if the strix_t or substr pointer is NULL, or the substring is invalid
 * - Additional error information should be handled externally
 */
int64_t strix_count_substr(const strix_t *strix, const char *substr);

/**
 * @brief Counts the occurrences of a specific substring represented by another strix_t
 *
 * This function counts how many times the specified strix_t (substrix) appears within the string of the given strix_t structure.
 * It returns the count of occurrences, or -1 in case of an error.
 *
 * @param strix Pointer to the strix_t structure to analyze
 * @param substrix Pointer to the strix_t structure representing the substring to count
 * @return int64_t The count of the specified substring, or -1 if there is an error
 *
 * Errors:
 * - Returns -1 if either strix or substrix is NULL, or the substrix string is invalid
 * - Additional error information should be handled externally
 */
int64_t strix_count_substrix(const strix_t *strix, const strix_t *substrix);

/**
 * @brief Creates a new strix_t containing characters from start to end with the given stride
 *
 * This function creates a new strix_t structure containing characters from the source strix,
 * starting at 'start', ending at 'end' (inclusive), and taking every 'stride'th character.
 * For example, with stride=2, it would take every second character.
 *
 * @param strix Pointer to the source strix_t structure
 * @param start Starting index in the source string (inclusive)
 * @param end Ending index in the source string (inclusive)
 * @param stride Step size between characters to include
 * @return strix_t* Pointer to the new strix_t structure, or NULL if there is an error
 *
 * Errors:
 * - Returns NULL if strix is NULL (sets STRIX_ERR_NULL_PTR)
 * - Returns NULL if start > end or end >= strix->len (sets STRIX_ERR_INVALID_BOUNDS)
 * - Returns NULL if stride is 0 (sets STRIX_ERR_INVALID_STRIDE)
 * - Returns NULL if memory allocation fails (sets STRIX_ERR_MALLOC_FAILED)
 * - Returns NULL if memory copy fails (sets STRIX_ERR_MEMCPY_FAILED)
 */
strix_t *strix_slice_by_stride(const strix_t *strix, size_t start, size_t end, size_t stride);

bool strix_delete_occurence(strix_t *strix, const char *substr);

typedef struct
{
    char *unique_char_arr;
    size_t len;
} char_arr_t;

char_arr_t *strix_find_unique_char(strix_t *strix);

void strix_free_char_arr(char_arr_t *char_arr);

position_t *strix_find_all_char(const strix_t *strix, const char chr);

strix_t *conv_file_to_strix(const char *file_path);

char *strix_to_cstr(strix_t *strix); // cleanup of the string is up to the user; can be freed using free(str)

void strix_free_position(position_t *pos);

strix_t *strix_create_empty(); // can't create empty with strix_create; but can with this

#endif /* A4921AE8_DB77_42E3_A83E_9D3D0C69BDE0 */