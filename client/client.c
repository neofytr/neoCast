#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <termios.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/select.h>

#define INITIAL_BUFFER_SIZE 4096
#define MAX_CMD_LENGTH 1024
#define LOOPBACK "127.0.0.1"

#define LOG_ERROR(msg, ...) fprintf(stderr, "[ERROR] " msg "\n", ##__VA_ARGS__)
#define LOG_INFO(msg, ...) fprintf(stdout, "[INFO] " msg "\n", ##__VA_ARGS__)

static ssize_t safe_read(int fd, char *buffer, size_t buffer_size, int timeout_seconds);
static ssize_t safe_write(int fd, const char *buffer, size_t buffer_size);
static char *dynamic_read(int fd, int timeout_seconds);
static bool send_message(int fd, const char *msg);
static char *read_password(const char *prompt);
static int interactive_shell(int server_fd);
static bool get_shell_prompt(int server_fd);
static void restore_terminal(struct termios *old_term);
static void prepare_terminal_raw(struct termios *old_term);

/**
 * Reads data from a file descriptor with timeout protection
 *
 * @param fd File descriptor to read from
 * @param buffer Buffer to store data
 * @param buffer_size Maximum size of the buffer
 * @param timeout_seconds Timeout in seconds (0 for no timeout)
 * @return Number of bytes read, 0 on timeout, -1 on error
 */
static ssize_t safe_read(int fd, char *buffer, size_t buffer_size, int timeout_seconds)
{
    if (!buffer || buffer_size == 0)
    {
        errno = EINVAL;
        return -1;
    }

    struct timeval timeout;
    fd_set read_fds;

    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);

    timeout.tv_sec = timeout_seconds;
    timeout.tv_usec = 0;

    int ready = select(fd + 1, &read_fds, NULL, NULL, timeout_seconds ? &timeout : NULL);

    if (ready < 0)
    {
        if (errno == EINTR)
            return 0; // Interrupted, treat as timeout
        LOG_ERROR("Select error: %s", strerror(errno));
        return -1;
    }

    if (ready == 0)
    {
        return 0; // Timeout
    }

    ssize_t bytes_read = read(fd, buffer, buffer_size - 1);

    if (bytes_read > 0)
    {
        buffer[bytes_read] = '\0'; // Null-terminate
    }

    return bytes_read;
}

/**
 * Writes data to a file descriptor with retry on interruption
 *
 * @param fd File descriptor to write to
 * @param buffer Data to write
 * @param buffer_size Size of the data
 * @return Number of bytes written, -1 on error
 */
static ssize_t safe_write(int fd, const char *buffer, size_t buffer_size)
{
    if (!buffer || buffer_size == 0)
        return 0;

    ssize_t total_written = 0;

    while (total_written < buffer_size)
    {
        ssize_t bytes_written = write(fd, buffer + total_written, buffer_size - total_written);

        if (bytes_written < 0)
        {
            if (errno == EINTR)
                continue; // Interrupted, retry
            LOG_ERROR("Write error: %s", strerror(errno));
            return -1;
        }

        if (!bytes_written)
            break; // Can't write any more

        total_written += bytes_written;
    }

    return total_written;
}

/**
 * Dynamically reads data from a file descriptor with automatic buffer resizing
 *
 * @param fd File descriptor to read from
 * @param timeout_seconds Timeout in seconds (0 for no timeout)
 * @return Dynamically allocated buffer with data (caller must free), NULL on error
 */
static char *dynamic_read(int fd, int timeout_seconds)
{
    size_t buffer_size = INITIAL_BUFFER_SIZE;
    size_t bytes_read_total = 0;
    char *buffer = malloc(buffer_size);

    if (!buffer)
    {
        LOG_ERROR("Memory allocation failed");
        return NULL;
    }

    while (1)
    {
        if (bytes_read_total >= buffer_size - 1)
        {
            size_t new_size = buffer_size * 2;
            char *new_buffer = realloc(buffer, new_size);
            if (!new_buffer)
            {
                LOG_ERROR("Memory reallocation failed");
                free(buffer);
                return NULL;
            }
            buffer = new_buffer;
            buffer_size = new_size;
        }

        ssize_t bytes_read = safe_read(fd, buffer + bytes_read_total,
                                       buffer_size - bytes_read_total,
                                       timeout_seconds);

        if (bytes_read < 0)
        {
            free(buffer);
            return NULL;
        }

        if (!bytes_read)
        { // EOF or timeout
            break;
        }

        bytes_read_total += bytes_read;

        // Stop reading on a newline
        if (buffer[bytes_read_total - 1] == '\n')
        {
            break;
        }
    }

    // Trim trailing whitespace
    while (bytes_read_total > 0 &&
           (buffer[bytes_read_total - 1] == '\r' ||
            buffer[bytes_read_total - 1] == '\n' ||
            buffer[bytes_read_total - 1] == ' '))
    {
        buffer[--bytes_read_total] = '\0';
    }

    buffer[bytes_read_total] = '\0';
    return buffer;
}

/**
 * Sends a message to the specified file descriptor with proper newline handling
 *
 * @param fd File descriptor to send to
 * @param msg Message to send
 * @return true on success, false on failure
 */
static bool send_message(int fd, const char *msg)
{
    if (!msg)
        return false;

    // Add CRLF to the message
    size_t msg_len = strlen(msg);
    char *buffer = malloc(msg_len + 3); // Room for message + \r\n\0

    if (!buffer)
    {
        LOG_ERROR("Memory allocation failed");
        return false;
    }

    strcpy(buffer, msg);
    strcat(buffer, "\r\n");

    ssize_t result = safe_write(fd, buffer, strlen(buffer));
    free(buffer);

    return result > 0;
}

/**
 * Securely reads a password without echoing characters
 *
 * @param prompt Text to display as password prompt
 * @return Dynamically allocated password string (caller must free), NULL on error
 */
static char *read_password(const char *prompt)
{
    struct termios old_term, new_term;
    char *password = malloc(INITIAL_BUFFER_SIZE);

    if (!password)
    {
        LOG_ERROR("Memory allocation failed");
        return NULL;
    }

    // Get the terminal attributes
    if (tcgetattr(STDIN_FILENO, &old_term) != 0)
    {
        LOG_ERROR("Failed to get terminal attributes: %s", strerror(errno));
        free(password);
        return NULL;
    }

    new_term = old_term;

    // Disable echo
    new_term.c_lflag &= ~(ECHO | ICANON);
    if (tcsetattr(STDIN_FILENO, TCSANOW, &new_term) != 0)
    {
        LOG_ERROR("Failed to set terminal attributes: %s", strerror(errno));
        free(password);
        return NULL;
    }

    printf("%s", prompt);
    fflush(stdout);

    // Read password
    if (fgets(password, INITIAL_BUFFER_SIZE, stdin) == NULL)
    {
        LOG_ERROR("Failed to read password");
        tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
        free(password);
        return NULL;
    }

    // Restore terminal
    if (tcsetattr(STDIN_FILENO, TCSANOW, &old_term) != 0)
    {
        LOG_ERROR("Failed to restore terminal attributes: %s", strerror(errno));
        // Continue anyway as the password was already read
    }

    // Remove newline
    size_t len = strlen(password);
    if (len > 0 && password[len - 1] == '\n')
    {
        password[len - 1] = '\0';
    }

    printf("\n");
    return password;
}

/**
 * Gets the initial shell prompt by sending a "cd ." command
 *
 * @param server_fd Socket connected to the server
 * @return true on success, false on failure
 */
static bool get_shell_prompt(int server_fd)
{
    // Send a dummy command to get the initial prompt
    if (!send_message(server_fd, "cd ."))
    {
        return false;
    }

    // Read and display the response (which includes the prompt)
    char *response = dynamic_read(server_fd, 5);
    if (!response)
    {
        return false;
    }

    printf("%s", response);
    fflush(stdout);
    free(response);

    return true;
}

/**
 * Prepares the terminal for raw mode input
 *
 * @param old_term Structure to store original terminal settings
 */
static void prepare_terminal_raw(struct termios *old_term)
{
    struct termios new_term;

    if (tcgetattr(STDIN_FILENO, old_term) != 0)
    {
        LOG_ERROR("Failed to get terminal attributes: %s", strerror(errno));
        return;
    }

    new_term = *old_term;

    // Configure for raw mode, but leave ISIG on to allow Ctrl+C to work
    new_term.c_lflag &= ~(ICANON | ECHO | ECHOE | ECHOK | ECHONL | IEXTEN);
    new_term.c_iflag &= ~(IXON | ICRNL | INLCR | IGNCR);
    new_term.c_oflag &= ~OPOST;

    // Set character timeout values
    new_term.c_cc[VMIN] = 1;  // Read at least 1 character
    new_term.c_cc[VTIME] = 0; // No timeout

    if (tcsetattr(STDIN_FILENO, TCSANOW, &new_term) != 0)
    {
        LOG_ERROR("Failed to set terminal attributes: %s", strerror(errno));
    }
}

/**
 * Restores the terminal to original settings
 *
 * @param old_term Original terminal settings to restore
 */
static void restore_terminal(struct termios *old_term)
{
    if (tcsetattr(STDIN_FILENO, TCSANOW, old_term) != 0)
    {
        LOG_ERROR("Failed to restore terminal attributes: %s", strerror(errno));
    }
}

/**
 * Handles interactive shell session between user and server
 *
 * @param server_fd Socket connected to the server
 * @return 0 on success, -1 on error
 */
static int interactive_shell(int server_fd)
{
    fd_set read_fds;
    char buffer[INITIAL_BUFFER_SIZE];
    struct termios old_term;
    char cmd_buffer[MAX_CMD_LENGTH] = {0};
    size_t cmd_len = 0;
    bool waiting_for_prompt = false;

    // Get initial shell prompt
    if (!get_shell_prompt(server_fd))
    {
        LOG_ERROR("Failed to get initial shell prompt");
        return -1;
    }

    // set terminal to raw mode
    prepare_terminal_raw(&old_term);

    while (true)
    {
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        FD_SET(server_fd, &read_fds);

        int max_fd = (STDIN_FILENO > server_fd ? STDIN_FILENO : server_fd) + 1;

        // wait for activity on either stdin or server socket
        int activity = select(max_fd, &read_fds, NULL, NULL, NULL);
        if (activity < 0)
        {
            if (errno == EINTR)
            {
                // interrupted system call, just retry
                continue;
            }
            LOG_ERROR("Select error: %s", strerror(errno));
            break;
        }

        // input from user
        if (FD_ISSET(STDIN_FILENO, &read_fds))
        {
            char input_char;
            ssize_t bytes_read = read(STDIN_FILENO, &input_char, 1);
            if (bytes_read <= 0)
            {
                if (bytes_read < 0)
                {
                    LOG_ERROR("Error reading from stdin: %s", strerror(errno));
                }
                break;
            }

            // Handle special key combinations
            if (input_char == 4 && cmd_len == 0)
            { // Ctrl+D on empty line
                break;
            }
            else if (input_char == '\r' || input_char == '\n')
            {
                // End of command - send to server
                if (cmd_len > 0)
                {
                    cmd_buffer[cmd_len] = '\0';

                    // Echo the newline locally
                    write(STDOUT_FILENO, "\r\n", 2);

                    // Send the complete command to server
                    if (safe_write(server_fd, cmd_buffer, cmd_len) < 0 ||
                        safe_write(server_fd, "\r\n", 2) < 0)
                    {
                        LOG_ERROR("Failed to send command to server");
                        break;
                    }

                    // Reset command buffer
                    cmd_len = 0;
                    memset(cmd_buffer, 0, MAX_CMD_LENGTH);
                    waiting_for_prompt = true;
                }
                else
                {
                    // Empty command - just send the newline
                    write(STDOUT_FILENO, "\r\n", 2);
                    safe_write(server_fd, "\r\n", 2);
                    waiting_for_prompt = true;
                }
            }
            else if (input_char == 127 || input_char == '\b')
            {
                // Backspace
                if (cmd_len > 0)
                {
                    cmd_len--;
                    cmd_buffer[cmd_len] = '\0';

                    // Echo the backspace (move cursor back, space, move cursor back)
                    write(STDOUT_FILENO, "\b \b", 3);
                }
            }
            else if (input_char >= 32 && input_char < 127)
            {
                // Regular printable character
                if (cmd_len < MAX_CMD_LENGTH - 1)
                {
                    cmd_buffer[cmd_len++] = input_char;

                    // Echo the character locally
                    write(STDOUT_FILENO, &input_char, 1);
                }
            }
        }

        // Response from server
        if (FD_ISSET(server_fd, &read_fds))
        {
            ssize_t bytes_read = safe_read(server_fd, buffer, sizeof(buffer), 0);
            if (bytes_read <= 0)
            {
                if (bytes_read < 0)
                {
                    LOG_ERROR("Error reading from server: %s", strerror(errno));
                }
                else
                {
                    LOG_INFO("Server closed connection");
                }
                break;
            }

            // Check for protocol messages
            if (!strncmp(buffer, "ERROR", 5))
            {
                LOG_ERROR("Server Error: %s", buffer);
                write(STDOUT_FILENO, buffer, bytes_read);
                write(STDOUT_FILENO, "\r\n", 2);
                break;
            }

            // Write the server's response to stdout
            if (safe_write(STDOUT_FILENO, buffer, bytes_read) < 0)
            {
                LOG_ERROR("Error writing to stdout: %s", strerror(errno));
                break;
            }

            // If we were waiting for a prompt, we now have it
            if (waiting_for_prompt)
            {
                waiting_for_prompt = false;
            }

            // Make sure output is displayed immediately
            fflush(stdout);
        }
    }

    // Restore terminal settings
    restore_terminal(&old_term);

    return 0;
}

/**
 * Main function - parse arguments and establish connection
 */
int main(int argc, char **argv)
{
    if (argc != 3)
    {
        LOG_ERROR("Incorrect Usage");
        LOG_ERROR("Correct Usage -> ./client username@ipaddress port");
        return EXIT_FAILURE;
    }

    char *username = NULL;
    char *ip_addr = NULL;
    char *at_sign = strchr(argv[1], '@');

    if (!at_sign)
    {
        LOG_ERROR("Invalid format: missing '@' symbol");
        return EXIT_FAILURE;
    }

    size_t username_len = at_sign - argv[1];
    username = malloc(username_len + 1);
    if (!username)
    {
        LOG_ERROR("Memory allocation failed");
        return EXIT_FAILURE;
    }
    strncpy(username, argv[1], username_len);
    username[username_len] = '\0';

    size_t ip_len = strlen(at_sign + 1);
    ip_addr = malloc(ip_len + 1);
    if (!ip_addr)
    {
        LOG_ERROR("Memory allocation failed");
        free(username);
        return EXIT_FAILURE;
    }
    strcpy(ip_addr, at_sign + 1);

    if (strcmp(ip_addr, "localhost") == 0)
    {
        free(ip_addr);
        ip_addr = strdup(LOOPBACK);
        if (!ip_addr)
        {
            LOG_ERROR("Memory allocation failed");
            free(username);
            return EXIT_FAILURE;
        }
    }

    char *endptr;
    int port = strtol(argv[2], &endptr, 10);
    if (*endptr || port <= 0 || port > 65535)
    {
        LOG_ERROR("Invalid port number: %s", argv[2]);
        free(username);
        free(ip_addr);
        return EXIT_FAILURE;
    }

    struct sockaddr_in server;
    memset(&server, 0, sizeof(struct sockaddr_in));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    if (inet_pton(AF_INET, ip_addr, &server.sin_addr) != 1)
    {
        LOG_ERROR("Invalid IPv4 address %s: %s", ip_addr, strerror(errno));
        free(username);
        free(ip_addr);
        return EXIT_FAILURE;
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        LOG_ERROR("Couldn't create a socket: %s", strerror(errno));
        free(username);
        free(ip_addr);
        return EXIT_FAILURE;
    }

    if (connect(server_fd, (struct sockaddr *)&server, sizeof(struct sockaddr_in)) < 0)
    {
        LOG_ERROR("Couldn't connect to the server IPv4: %s Port: %d -> %s",
                  ip_addr, port, strerror(errno));
        close(server_fd);
        free(username);
        free(ip_addr);
        return EXIT_FAILURE;
    }

    LOG_INFO("Connected to server at %s:%d", ip_addr, port);

    free(ip_addr);

    if (!send_message(server_fd, username))
    {
        LOG_ERROR("Failed to send username");
        close(server_fd);
        free(username);
        return EXIT_FAILURE;
    }

    free(username);

    bool authenticated = false;
    for (int attempts = 0; attempts < 3; attempts++)
    {
        char *server_response = dynamic_read(server_fd, 10);
        if (!server_response)
        {
            LOG_ERROR("Server did not respond to authentication request");
            close(server_fd);
            return EXIT_FAILURE;
        }

        if (strcmp(server_response, "PASSWORD_REQUEST") != 0)
        {
            LOG_ERROR("Invalid server response during authentication: %s", server_response);
            free(server_response);
            close(server_fd);
            return EXIT_FAILURE;
        }
        free(server_response);

        char *password = read_password("Enter password: ");
        if (!password)
        {
            close(server_fd);
            return EXIT_FAILURE;
        }

        if (!send_message(server_fd, password))
        {
            LOG_ERROR("Failed to send password");
            free(password);
            close(server_fd);
            return EXIT_FAILURE;
        }

        // Clear password from memory for security
        memset(password, 0, strlen(password));
        free(password);

        char *auth_response = dynamic_read(server_fd, 10);
        if (!auth_response)
        {
            LOG_ERROR("Failed to receive authentication response");
            close(server_fd);
            return EXIT_FAILURE;
        }

        if (!strcmp(auth_response, "AUTHENTICATED"))
        {
            LOG_INFO("Authentication successful");
            free(auth_response);
            authenticated = true;
            break;
        }

        LOG_ERROR("Authentication failed: %s", auth_response);
        free(auth_response);
    }

    if (!authenticated)
    {
        LOG_ERROR("Max login attempts reached");
        close(server_fd);
        return EXIT_FAILURE;
    }

    int result = interactive_shell(server_fd);

    close(server_fd);
    return !result ? EXIT_SUCCESS : EXIT_FAILURE;
}