# Strix String Manipulation Library 🪢

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A modern, efficient, and thread-safe C library for string manipulation that goes beyond traditional null-terminated strings. Strix introduces a robust `strix_t` structure for explicit length tracking and safe binary data handling.

## ✨ Features

- 🔒 Thread-safe error handling
- 📏 Explicit length tracking
- 🎯 Custom memory allocation
- 🛡️ Robust error checking
- 🧵 Safe string manipulation

## 📦 Installation

```bash
gcc main.c strix.o -o main
```

The library binary (`strix.o`) can be found in the `/binaries/` directory.

## 🏗️ Core Data Structures

### strix_t
```c
typedef struct {
    char *str;   // Pointer to the string data
    size_t len;  // Length of the string
} strix_t;
```

### strix_arr_t
```c
typedef struct {
    strix_t **strix_arr;
    size_t len;
} strix_arr_t;
```

## Macros

### `STRIX_FORMAT`

Format macro for printf-style functions to print strix_t objects.

### `STRIX_PRINT(strix)`

Expands to length and strix pointer for use with STRIX_FORMAT.

Example usage to print a strix string:

`printf("strix string: "STRIX_FORMAT"\n", STRIX_PRINT(strix));`

## 📚 API Reference

THIS IS NOT THE COMPLETE API, THERE ARE MANY MORE FUNCTIONS.

For the complete detailed API reference , consult the file: `/header/strix.h`

### String Creation and Management

| Function | Description | Signature |
|----------|-------------|-----------|
| `strix_create` | Creates a new strix_t from a C-style string | `strix_t *strix_create(const char *str)` |
| `strix_duplicate` | Creates a deep copy of an existing strix_t | `strix_t *strix_duplicate(const strix_t *strix)` |
| `strix_modify` | Modifies an existing strix_t with a new string | `bool strix_modify(strix_t *strix, const char *str)` |
| `strix_clear` | Clears the contents of a strix_t structure | `bool strix_clear(strix_t *strix)` |
| `strix_free` | Frees memory allocated for a strix_t | `void strix_free(strix_t *string)` |

### String Operations

| Function | Description | Signature |
|----------|-------------|-----------|
| `strix_concat` | Concatenates two strix_t structures | `bool strix_concat(strix_t *strix_dest, const strix_t *strix_src)` |
| `strix_append` | Appends a C-style string to a strix_t | `bool strix_append(strix_t *strix, const char *str)` |
| `strix_insert` | Inserts one strix_t into another at a position | `bool strix_insert(strix_t *strix_dest, strix_t *strix_src, size_t pos)` |
| `strix_insert_str` | Inserts a substring at a position | `bool strix_insert_str(strix_t *strix, size_t pos, const char *substr)` |
| `strix_erase` | Erases a portion of the string | `bool strix_erase(strix_t *strix, size_t len, size_t pos)` |

### Search and Comparison

| Function | Description | Signature |
|----------|-------------|-----------|
| `strix_at` | Gets character at specified index | `char strix_at(const strix_t *strix, size_t index)` |
| `strix_equal` | Compares two strix_t structures | `int strix_equal(const strix_t *strix_one, const strix_t *strix_two)` |
| `strix_find` | Finds first occurrence of substring | `int64_t strix_find(const strix_t *strix, const char *substr)` |
| `strix_find_all` | Finds all occurrences of substring | `position_t *strix_find_all(const strix_t *strix, const char *substr)` |
| `strix_find_subtrix` | Finds first occurrence of one strix_t in another | `int64_t strix_find_subtrix(const strix_t *strix_one, const strix_t *strix_two)` |

### Split and Join Operations

| Function | Description | Signature |
|----------|-------------|-----------|
| `strix_split_by_delim` | Splits by delimiter | `strix_arr_t *strix_split_by_delim(const strix_t *strix, const char delim)` |
| `strix_split_by_substr` | Splits by substring | `strix_arr_t *strix_split_by_substr(const strix_t *strix, const char *substr)` |
| `strix_join_via_delim` | Joins with delimiter | `strix_t *strix_join_via_delim(const strix_t **strix_arr, size_t len, const char delim)` |
| `strix_join_via_substr` | Joins with substring | `strix_t *strix_join_via_substr(const strix_t **strix_arr, size_t len, const char *substr)` |

### Trim Operations

| Function | Description | Signature |
|----------|-------------|-----------|
| `strix_trim_whitespace` | Removes whitespace from both ends of a strix_t in place | `bool strix_trim_whitespace(strix_t *strix)`|
| `strix_trim_char` | Removes a specified character from both ends of a strix_t in place | `bool strix_trim_char(strix_t *strix, const char trim)` |

Here’s the table format for the conversion functions you requested:

### Conversion Operations

| Function                    | Description                                                                          | Signature                                              |
|-----------------------------|--------------------------------------------------------------------------------------|--------------------------------------------------------|
| `strix_to_double`            | Converts a strix_t to a double value. Handles signs, decimals, and errors.          | `double strix_to_double(strix_t *strix)`               |
| `strix_to_signed_int`        | Converts a strix_t to a signed 64-bit integer. Handles signs and overflow checks.    | `int64_t strix_to_signed_int(strix_t *strix)`          |
| `strix_to_unsigned_int`      | Converts a strix_t to an unsigned 64-bit integer. Handles positive sign and overflow checks. | `uint64_t strix_to_unsigned_int(strix_t *strix)`      |

## 🎯 Usage Example

```c
#include "strix.h"

int main() {
    strix_t *hello = strix_create("Hello");
    strix_t *world = strix_create("World");

    // Concatenate strings
    strix_concat(hello, world);
    printf(STRIX_FORMAT, STRIX_PRINT(hello)); // Output: HelloWorld

    strix_free(hello);
    strix_free(world);
    return 0;
}
```

### Error Handling

The **Strix String Manipulation Library** integrates a robust and thread-safe error-handling system to manage various failure scenarios. 

THE FOLLOWING DESCRIPTION IS NOT EXHAUSTIVE

For detailed reference to the error-handling system, consult the file:

`/header/strix_errno.h`

### Error Codes
The `strix_error_t` enumeration defines all possible error codes that may be returned by the library functions:

| Error Code                        | Description                                    |
|-----------------------------------|------------------------------------------------|
| `STRIX_SUCCESS`                   | Operation completed successfully              |
| `STRIX_ERR_NULL_PTR`              | Null pointer passed as argument               |
| `STRIX_ERR_MALLOC_FAILED`         | Dynamic memory allocation operation failed    |
| `STRIX_ERR_MEMCPY_FAILED`         | Memory copy operation failed                  |
| `STRIX_ERR_MEMMOVE_FAILED`        | Memory move operation failed                  |
| `STRIX_ERR_INVALID_LENGTH`        | Invalid string length specified or computed   |
| `STRIX_ERR_EMPTY_STRING`          | Empty string provided where non-empty required|
| `STRIX_ERR_STRIX_STR_NULL`        | Null string in the strix structure provided   |
| `STRIX_ERR_INVALID_POS`           | Invalid strix string position provided        |
| `STRIX_ERR_OUT_OF_BOUNDS_ACCESS`  | Out of bounds element access                  |
| `STRIX_ERR_INVALID_BOUNDS`        | Invalid bounds given for slicing              |

### Thread-Local Error State
Each thread maintains its own independent error state in the `strix_errno` variable, initialized to `STRIX_SUCCESS`. This ensures thread safety and allows simultaneous operations across multiple threads without interference.

### Error Messages
The library provides a static array of human-readable error messages, indexed by their corresponding error codes:

```c
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
};
```

### Error Handling API
#### `void strix_perror(const char *prefix)`
Prints a formatted error message to `stderr`, combining the provided prefix and the descriptive error message corresponding to the current `strix_errno` value.

**Example Usage:**
```c
if (!strix_some_function(s)) {
    strix_perror("Failed to process string");
    // Output: "Failed to process string: <error message>"
}
```

#### `strix_error_t strix_get_error(void)`
Retrieves the current error code stored in the thread-local `strix_errno`.

**Example Usage:**
```c
if (strix_get_error() == STRIX_ERR_MALLOC_FAILED) {
    // Handle memory allocation failure
}
```


## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request