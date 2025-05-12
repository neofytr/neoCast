// Improved Remote Shell Client

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
#include <sys/select.h>

#define MAX_STRLEN 4096
#define LOOPBACK "127.0.0.1"

// Logging macros
#define LOG_ERROR(msg, ...) fprintf(stderr, "[ERROR] " msg "\n", ##__VA_ARGS__)
#define LOG_INFO(msg, ...) fprintf(stdout, "[INFO] " msg "\n", ##__VA_ARGS__)

// Safe read with timeout
static ssize_t safe_read(int fd, char *buffer, size_t buffer_size)
{
    struct timeval timeout;
    fd_set read_fds;

    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);

    timeout.tv_sec = 10; // 10-second timeout
    timeout.tv_usec = 0;

    int ready = select(fd + 1, &read_fds, NULL, NULL, &timeout);

    if (ready < 0)
    {
        LOG_ERROR("Select error: %s", strerror(errno));
        return -1;
    }

    if (ready == 0)
    {
        LOG_ERROR("Read timeout");
        return 0;
    }

    ssize_t bytes_read = read(fd, buffer, buffer_size - 1);

    if (bytes_read > 0)
    {
        buffer[bytes_read] = '\0'; // Null-terminate
    }

    return bytes_read;
}

// Safe write with error handling
static ssize_t safe_write(int fd, const char *buffer, size_t buffer_size)
{
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

        total_written += bytes_written;
    }

    return total_written;
}

// Receive from server with protocol-aware termination
static char *receive_from_server(int server_fd)
{
    char *buffer = malloc(MAX_STRLEN + 1);
    if (!buffer)
    {
        LOG_ERROR("Memory allocation failed");
        return NULL;
    }

    memset(buffer, 0, MAX_STRLEN + 1);
    ssize_t bytes_read = safe_read(server_fd, buffer, MAX_STRLEN);

    if (bytes_read <= 0)
    {
        free(buffer);
        return NULL;
    }

    // Trim trailing whitespace and newlines
    while (bytes_read > 0 && (buffer[bytes_read - 1] == '\r' ||
                              buffer[bytes_read - 1] == '\n' ||
                              buffer[bytes_read - 1] == ' '))
    {
        buffer[--bytes_read] = '\0';
    }

    return buffer;
}

// Send to server with protocol-aware termination
static bool send_to_server(int server_fd, const char *msg)
{
    if (!msg)
        return false;

    char buffer[MAX_STRLEN + 3]; // Room for message + \r\n\0
    snprintf(buffer, sizeof(buffer), "%s\r\n", msg);

    ssize_t result = safe_write(server_fd, buffer, strlen(buffer));
    return result > 0;
}

// Read password securely without echoing
static char *read_password(const char *prompt)
{
    struct termios old_term, new_term;
    char *password = malloc(MAX_STRLEN);

    if (!password)
    {
        LOG_ERROR("Memory allocation failed");
        return NULL;
    }

    // Get the terminal attributes
    tcgetattr(STDIN_FILENO, &old_term);
    new_term = old_term;

    // Disable echo
    new_term.c_lflag &= ~(ECHO | ICANON);
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);

    printf("%s", prompt);
    fflush(stdout);

    // Read password
    if (fgets(password, MAX_STRLEN, stdin) == NULL)
    {
        LOG_ERROR("Failed to read password");
        tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
        free(password);
        return NULL;
    }

    // Restore terminal
    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);

    // Remove newline
    size_t len = strlen(password);
    if (len > 0 && password[len - 1] == '\n')
    {
        password[len - 1] = '\0';
    }

    printf("\n");
    return password;
}

// Interactive shell session
static int interactive_shell(int server_fd)
{
    fd_set read_fds;
    char buffer[MAX_STRLEN];

    while (true)
    {
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        FD_SET(server_fd, &read_fds);

        int max_fd = (STDIN_FILENO > server_fd ? STDIN_FILENO : server_fd) + 1;

        // Wait for activity on either stdin or server socket
        int activity = select(max_fd, &read_fds, NULL, NULL, NULL);
        if (activity < 0)
        {
            LOG_ERROR("Select error: %s", strerror(errno));
            break;
        }

        // Input from user to send to server
        if (FD_ISSET(STDIN_FILENO, &read_fds))
        {
            ssize_t bytes_read = read(STDIN_FILENO, buffer, sizeof(buffer) - 1);
            if (bytes_read <= 0)
                break;

            buffer[bytes_read] = '\0';
            if (!send_to_server(server_fd, buffer))
                break;
        }

        // Response from server
        if (FD_ISSET(server_fd, &read_fds))
        {
            char *response = receive_from_server(server_fd);
            if (!response)
                break;

            // Check for protocol messages
            if (strncmp(response, "ERROR", 5) == 0)
            {
                LOG_ERROR("Server Error: %s", response);
                free(response);
                break;
            }

            // Print server response
            printf("%s", response);
            free(response);
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        LOG_ERROR("Incorrect Usage");
        LOG_ERROR("Correct Usage -> ./client username@ipaddress port");
        return EXIT_FAILURE;
    }

    // Parse username and IP
    char username[MAX_STRLEN] = {0};
    char ip_addr[INET_ADDRSTRLEN] = {0};
    char *ptr = argv[1];
    int index = 0;

    // Extract username
    while (*ptr != '@' && *ptr != '\0')
    {
        username[index++] = *ptr++;
    }
    username[index] = '\0';

    // Check for '@' symbol
    if (*ptr != '@')
    {
        LOG_ERROR("Invalid format: missing '@' symbol");
        return EXIT_FAILURE;
    }

    // Skip the '@' symbol
    ptr++;

    // Extract IP address
    index = 0;
    while (*ptr != '\0')
    {
        ip_addr[index++] = *ptr++;
    }
    ip_addr[index] = '\0';

    // Handle localhost
    if (strcmp(ip_addr, "localhost") == 0)
    {
        strcpy(ip_addr, LOOPBACK);
    }

    // Parse port number
    char *endptr;
    int port = strtol(argv[2], &endptr, 10);
    if (*endptr || port <= 0 || port > 65535)
    {
        LOG_ERROR("Invalid port number: %s", argv[2]);
        return EXIT_FAILURE;
    }

    // Prepare server address
    struct sockaddr_in server;
    memset(&server, 0, sizeof(struct sockaddr_in));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    // Convert IP address
    if (inet_pton(AF_INET, ip_addr, &server.sin_addr) != 1)
    {
        LOG_ERROR("Invalid IPv4 %s: %s", ip_addr, strerror(errno));
        return EXIT_FAILURE;
    }

    // Create socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        LOG_ERROR("Couldn't create a socket: %s", strerror(errno));
        return EXIT_FAILURE;
    }

    // Connect to server
    if (connect(server_fd, (struct sockaddr *)&server, sizeof(struct sockaddr_in)) < 0)
    {
        LOG_ERROR("Couldn't connect to the server IPv4: %s Port: %d -> %s",
                  ip_addr, port, strerror(errno));
        close(server_fd);
        return EXIT_FAILURE;
    }

    LOG_INFO("Connected to server at %s:%d", ip_addr, port);

    // Send username
    if (!send_to_server(server_fd, username))
    {
        LOG_ERROR("Failed to send username");
        close(server_fd);
        return EXIT_FAILURE;
    }

    // Authentication loop
    bool authenticated = false;
    for (int attempts = 0; attempts < 3; attempts++)
    {
        // Receive password request
        char *server_response = receive_from_server(server_fd);
        if (!server_response || strcmp(server_response, "PASSWORD_REQUEST") != 0)
        {
            LOG_ERROR("Invalid server response during authentication");
            free(server_response);
            close(server_fd);
            return EXIT_FAILURE;
        }
        free(server_response);

        // Prompt for password
        char *password = read_password("Enter password: ");
        if (!password)
        {
            close(server_fd);
            return EXIT_FAILURE;
        }

        // Send password
        if (!send_to_server(server_fd, password))
        {
            LOG_ERROR("Failed to send password");
            free(password);
            close(server_fd);
            return EXIT_FAILURE;
        }

        // Receive authentication result
        char *auth_response = receive_from_server(server_fd);
        if (!auth_response)
        {
            LOG_ERROR("Failed to receive authentication response");
            free(password);
            close(server_fd);
            return EXIT_FAILURE;
        }

        if (strcmp(auth_response, "AUTHENTICATED") == 0)
        {
            LOG_INFO("Authentication successful");
            free(password);
            free(auth_response);
            authenticated = true;
            break;
        }

        // Authentication failed
        LOG_ERROR("Authentication failed: %s", auth_response);
        free(password);
        free(auth_response);
    }

    // Exit if authentication failed
    if (!authenticated)
    {
        LOG_ERROR("Max login attempts reached");
        close(server_fd);
        return EXIT_FAILURE;
    }

    // Start interactive shell session
    int result = interactive_shell(server_fd);

    // Cleanup
    close(server_fd);
    return result == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}