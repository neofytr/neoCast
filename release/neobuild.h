#ifndef NEOBUILD_H
#define NEOBUILD_H

#include "dynarr/inc/dynarr.h"
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>

// for pid_t and mode_t
#include <sys/types.h>

#include <stdio.h>

/**
 * Enum representing different compiler types that can be used.
 */
typedef enum
{
    LD, // the GNU linker
    AS, // the GNU assembler
    GCC,            /**< GNU Compiler Collection */
    CLANG,          /**< Clang compiler */
    GLOBAL_DEFAULT, /**< Use the globally set default compiler */
} neocompiler_t;

/**
 * Sets the global default compiler to be used when GLOBAL_DEFAULT is specified.
 *
 * @param compiler The compiler type to set as the global default.
 */
void neo_set_global_default_compiler(neocompiler_t compiler);

/**
 * Gets the current global default compiler setting.
 *
 * @return The currently set global default compiler.
 */
neocompiler_t neo_get_global_default_compiler();

/**
 * Enum representing different logging levels for the neo build system.
 */
typedef enum
{
    ERROR,   /**< Error level for critical issues */
    WARNING, /**< Warning level for potential issues */
    INFO,    /**< Info level for general information */
    DEBUG    /**< Debug level for detailed debugging information */
} neolog_level_t;

/**
 * Structure representing a key-value configuration pair.
 */
typedef struct
{
    char *key;   /**< Configuration key */
    char *value; /**< Configuration value */
} neoconfig_t;

/**
 * Macro for logging messages with the specified log level.
 *
 * @param level The log level for the message (ERROR, WARNING, INFO, or DEBUG).
 * @param msg The message to log.
 */
#define NEO_LOG(level, msg)                         \
    do                                              \
    {                                               \
        switch (level)                              \
        {                                           \
        case ERROR:                                 \
            fprintf(stderr, "[ERROR] %s\n", msg);   \
            break;                                  \
        case WARNING:                               \
            fprintf(stderr, "[WARNING] %s\n", msg); \
            break;                                  \
        case INFO:                                  \
            fprintf(stdout, "[INFO] %s\n", msg);    \
            break;                                  \
        case DEBUG:                                 \
            fprintf(stdout, "[DEBUG] %s\n", msg);   \
            break;                                  \
        default:                                    \
            fprintf(stdout, "[UNKNOWN] %s\n", msg); \
            break;                                  \
        }                                           \
    } while (0)

// check if the neo.c build C file has changed since the previous compilation of it to neo
// (done by checking the modified date/time of neo.c; if this time comes after the last modified of neo.c, we need to rebuild neo from this new neo.c)

// buildneo, build.c and build should be in the same directory
bool neorebuild(const char *build_file, char **argv);

/**
 * Enum representing different shell types.
 */
typedef enum
{
    DASH, /**< Dash shell */
    BASH, /**< Bash shell */
    SH    /**< Standard shell (sh) */
} neoshell_t;

/**
 * Structure representing a command to be executed.
 */
typedef struct
{
    dyn_arr_t *args;  /**< Dynamic array storing command arguments. */
    neoshell_t shell; /**< Shell type used to execute the command. */
} neocmd_t;

/**
 * Appends arguments to a command structure.
 *
 * This macro simplifies appending multiple arguments to a `neocmd_t` object.
 * It automatically adds a terminating `NULL` argument.
 *
 * @param neocmd_ptr Pointer to the `neocmd_t` object.
 * @param ... Variable arguments representing the command arguments to append.
 */
#define neocmd_append(neocmd_ptr, ...) neocmd_append_null((neocmd_ptr), __VA_ARGS__, NULL)

#define neo_link(compiler, executable, linker_flags, forced_linking, ...) neo_link_null((compiler), (executable), (linker_flags), (forced_linking), __VA_ARGS__, NULL)

/**
 * Generates a string representation of a label, ensuring compatibility with filenames containing whitespaces.
 *
 * @param label The label to be converted to a string.
 * @return String literal representation of the label.
 */
#define LABEL_WITH_SPACES(label) #label

/**
 * Creates a new command structure.
 *
 * @param shell The shell type to be used for executing the command.
 * @return Pointer to a newly allocated `neocmd_t` structure.
 */
neocmd_t *neocmd_create(neoshell_t shell);

/**
 * Deletes a command structure and frees allocated resources.
 *
 * @param neocmd Pointer to the `neocmd_t` object to be deleted.
 * @return true if the command was successfully deleted, false otherwise.
 */
bool neocmd_delete(neocmd_t *neocmd);

/*
 * This function runs a command asynchronously by forking a child process.
 *
 * - The child process will execute independently and will not be waited for within this function.
 * - The parent must explicitly call waitpid(pid) later to retrieve the exit status.
 * - If the parent process exits before the child, the child process will be reparented to init (PID 1),
 *   which will eventually clean it up.
 * - If the parent does not call waitpid(), the child remains in a "zombie" state after termination.
 *   - A zombie process retains only its PID and exit status in the process table.
 *   - It no longer executes or consumes memory, but it persists until the parent calls waitpid().
 *   - If the parent itself terminates, init adopts the zombie process and clears it.
 * - All process resources (memory, file descriptors, etc.) are freed upon child exit,
 *   except for the exit status, which remains in the process table until reaped.
 */

/**
 * Runs a command asynchronously.
 *
 * This function forks a new process to execute the command in the background.
 *
 * @param neocmd Pointer to the command structure to be executed.
 * @return The process ID (`pid_t`) of the child process if successful, or `-1` on failure.
 */
pid_t neocmd_run_async(neocmd_t *neocmd);

/**
 * Runs the given command synchronously and waits for it to complete.
 *
 * @param neocmd Pointer to the command structure.
 * @param status Pointer to an integer where the process exit status will be stored.
 *               - If the process exits normally, `*status` will hold the exit code (0-255).
 *               - If the process is terminated by a signal, `*status` will hold the signal number.
 * @param code Pointer to an integer where the termination reason will be stored.
 *             - It will be set to one of the `si_code` values (e.g., `CLD_EXITED`, `CLD_KILLED`, `CLD_DUMPED`, etc.).
 * @param print_status_desc If `true`, prints a description of the termination status.
 *
 * @return `true` if the process was successfully waited on, `false` otherwise.
 */
bool neocmd_run_sync(neocmd_t *neocmd, int *status, int *code, bool print_status_desc);

/**
 * Waits for a child process to terminate.
 *
 * @param pid The process ID (`pid_t`) of the child process to wait for.
 * @param status Pointer to an integer where the process exit status will be stored.
 *               - If the process exits normally, `*status` will hold the exit code (0-255).
 *               - If the process is terminated by a signal, `*status` will hold the signal number.
 * @param code Pointer to an integer where the termination reason will be stored.
 *             - It will be set to one of the `si_code` values (e.g., `CLD_EXITED`, `CLD_KILLED`, `CLD_DUMPED`, etc.).
 * @param should_print If `true`, prints information about the process termination.
 *
 * @return `true` if the process was successfully waited on, `false` otherwise.
 */
bool neoshell_wait(pid_t pid, int *status, int *code, bool should_print);

/**
 * Appends arguments to a command structure.
 *
 * This function allows appending multiple arguments to a command dynamically.
 * The arguments list must be NULL-terminated.
 *
 * @param neocmd Pointer to the `neocmd_t` object.
 * @param ... Variable argument list representing the command arguments.
 * @return `true` if the arguments were successfully appended, `false` otherwise.
 */
bool neocmd_append_null(neocmd_t *neocmd, ...);

/**
 * Generates a string representation of the command.
 *
 * This function converts a `neocmd_t` object into a formatted string representation.
 * The caller is responsible for freeing the returned string using `free()`.
 *
 * @param neocmd Pointer to the command structure.
 * @return A dynamically allocated string containing the command representation.
 */
const char *neocmd_render(neocmd_t *neocmd);

/**
 * Checks if the build file has changed since the previous compilation and rebuilds if necessary.
 *
 * @param build_file Path to the build file to check.
 * @param argv The command line arguments to pass to the rebuild process.
 * @return true if a rebuild was performed successfully, false otherwise.
 */
bool neorebuild(const char *build_file, char **argv);

/**
 * Creates directories recursively (similar to mkdir -p).
 *
 * @param dir_path Path to the directory to create.
 * @param mode Permission mode for the created directories.
 * @return true if directories were created successfully, false otherwise.
 */
bool neo_mkdir(const char *dir_path, mode_t mode);

/**
 * Parses a configuration file into an array of key-value pairs.
 *
 * @param config_file_path Path to the configuration file to parse.
 * @param config_arr_len Pointer to a size_t variable where the length of the resulting array will be stored.
 * @return An array of neoconfig_t structures containing the parsed configuration.
 */
neoconfig_t *neo_parse_config(const char *config_file_path, size_t *config_arr_len);

/**
 * Frees the memory allocated for a configuration array.
 *
 * @param config_arr The configuration array to free.
 * @param config_arr_len The length of the configuration array.
 * @return true if the memory was successfully freed, false otherwise.
 */
bool neo_free_config(neoconfig_t *config_arr, size_t config_arr_len);

/**
 * Parses configuration options from command line arguments.
 *
 * @param argv The command line arguments to parse.
 * @param config_arr_len Pointer to a size_t variable where the length of the resulting array will be stored.
 * @return An array of neoconfig_t structures containing the parsed configuration.
 */
neoconfig_t *neo_parse_config_arg(char **argv, size_t *config_arr_len);

// if output is NULL, the name of the output object file is the same as the source file (with removed .c)
// and is placed in the same directory and the source file
// if the compiler flags are NULL, the only compiler flag used is "-c", which specifies compilation to object files
// will compile only if the output file doesn't exist or if the object file is older than the source file

/**
 * Compiles a source file to an object file using the specified compiler.
 *
 * @param compiler The compiler to use for compilation.
 * @param source Path to the source file to compile.
 * @param output Path to the output object file (can be NULL to use default naming).
 * @param compiler_flags Additional compiler flags to use (can be NULL to use defaults).
 * @param force_compilation If true, forces compilation even if the object file is newer than the source.
 * @return true if compilation was successful, false otherwise.
 */
bool neo_compile_to_object_file(neocompiler_t compiler, const char *source, const char *output, const char *compiler_flags, bool force_compilation);

// links the provided object files with each other and with glibc (always) along with appending the linker flags provided to produce executable
// the object files are provided to the linker in the order in which they are specified in the function
// the linker flags are appended at the end in the order they are present in the linker_flags strig
// the executable parameter is required
// enabling forced linking prevents timestamp caching and always results in linking
// disabling it results in linking only if any of the object files are newer than the executable provided (if it exists)
// if the executable doesn't exist, forced_linking doesn't have any effect
bool neo_link_null(neocompiler_t compiler, const char *executable, const char *linker_flags, bool forced_linking, ...);

#ifdef NEO_REMOVE_PREFIX

#define cmd_create neocmd_create
#define cmd_delete neocmd_delete
#define cmd_run_async neocmd_run_async
#define cmd_run_sync neocmd_run_sync
#define cmd_append neocmd_append
#define cmd_append_null neocmd_append_null
#define cmd_render neocmd_render
#define shell_wait neoshell_wait

#endif /* NEO_REMOVE_PREFIX */

#endif /* NEOBUILD_H */
