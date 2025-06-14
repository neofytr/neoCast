#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <pty.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <shadow.h>
#include <crypt.h>
#include <pwd.h>
#include <sys/types.h>
#include <signal.h>
#include <fcntl.h>

#define MAX_STRLEN 4096
#define MAX_LOGIN_ATTEMPTS 3
#define BACKLOG 5

#define LOG_ERROR(msg, ...) fprintf(stderr, "[ERROR] " msg "\n", ##__VA_ARGS__)
#define LOG_INFO(msg, ...) fprintf(stdout, "[INFO] " msg "\n", ##__VA_ARGS__)

static void usage_error(void);
static ssize_t safe_read(int fd, char *buffer, size_t buffer_size);
static ssize_t safe_write(int fd, const char *buffer, size_t buffer_size);
static char *receive_from_client(int client_fd);
static bool send_to_client(int client_fd, const char *msg);
static bool authenticate_user(const char *username, const char *password);
static bool drop_privileges(const char *username);
static void cleanup_and_close(int client_fd, int master_fd, pid_t child_pid);

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
        if (errno == EINTR)
            return 0; // interrupted, treat as timeout
        LOG_ERROR("Select error: %s", strerror(errno));
        return -1;
    }

    if (!ready)
    {
        return 0; // timeout
    }

    ssize_t bytes_read = read(fd, buffer, buffer_size - 1);

    if (bytes_read > 0)
    {
        buffer[bytes_read] = '\0'; // null-terminate
    }

    return bytes_read;
}

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
                continue; // interrupted, retry
            LOG_ERROR("Write error: %s", strerror(errno));
            return -1;
        }

        if (!bytes_written)
            break; // can't write any more

        total_written += bytes_written;
    }

    return total_written;
}

static char *receive_from_client(int client_fd)
{
    char *buffer = malloc(MAX_STRLEN + 1);
    if (!buffer)
    {
        LOG_ERROR("Memory allocation failed");
        return NULL;
    }

    memset(buffer, 0, MAX_STRLEN + 1);
    ssize_t bytes_read = safe_read(client_fd, buffer, MAX_STRLEN);

    if (bytes_read <= 0)
    {
        free(buffer);
        return NULL;
    }

    // remove trailing whitespace
    while (bytes_read > 0 && (buffer[bytes_read - 1] == '\r' ||
                              buffer[bytes_read - 1] == '\n' ||
                              buffer[bytes_read - 1] == ' '))
    {
        buffer[--bytes_read] = '\0';
    }

    return buffer;
}

static bool send_to_client(int client_fd, const char *msg)
{
    if (!msg)
        return false;

    char buffer[MAX_STRLEN + 3]; // Room for message + \r\n\0
    snprintf(buffer, sizeof(buffer), "%s\r\n", msg);

    ssize_t result = safe_write(client_fd, buffer, strlen(buffer));
    return result > 0;
}

static bool authenticate_user(const char *username, const char *password)
{
    if (!username || !password)
        return false;

    struct spwd *shadow_entry = getspnam(username);
    if (!shadow_entry)
    {
        LOG_ERROR("User not found: %s", username);
        return false;
    }

    char *encrypted = crypt(password, shadow_entry->sp_pwdp);
    return encrypted && !strcmp(encrypted, shadow_entry->sp_pwdp);
}

static bool drop_privileges(const char *username)
{
    if (!username)
        return false;

    struct passwd *pw = getpwnam(username);
    if (!pw)
    {
        LOG_ERROR("User not found in passwd file");
        return false;
    }

    // change to user's home directory
    if (chdir(pw->pw_dir) != 0)
    {
        LOG_ERROR("Failed to change directory to %s: %s", pw->pw_dir, strerror(errno));
        return false;
    }

    // set group and user IDs
    if (setgid(pw->pw_gid) != 0)
    {
        LOG_ERROR("Failed to set group ID: %s", strerror(errno));
        return false;
    }

    if (setuid(pw->pw_uid) != 0)
    {
        LOG_ERROR("Failed to set user ID: %s", strerror(errno));
        return false;
    }

    return true;
}

static void cleanup_and_close(int client_fd, int master_fd, pid_t child_pid)
{
    if (child_pid > 0)
    {
        kill(child_pid, SIGTERM);
        waitpid(child_pid, NULL, 0);
    }

    if (master_fd >= 0)
        close(master_fd);
    if (client_fd >= 0)
        close(client_fd);
}

void *client_handler(void *arg)
{
    long long client_fd = (long long)arg;
    int master_fd = -1;
    pid_t child_pid = -1;
    char *username = NULL;

    // Receive username
    username = receive_from_client(client_fd);
    if (!username)
    {
        LOG_ERROR("Failed to receive username");
        send_to_client(client_fd, "ERROR: Username receive failed");
        close(client_fd);
        return NULL;
    }

    LOG_INFO("Received username: %s", username);

    // authentication loop
    bool authenticated = false;
    for (int attempts = 0; attempts < MAX_LOGIN_ATTEMPTS; attempts++)
    {
        send_to_client(client_fd, "PASSWORD_REQUEST");
        char *password = receive_from_client(client_fd);

        if (!password)
        {
            LOG_ERROR("Failed to receive password");
            send_to_client(client_fd, "ERROR: Password receive failed");
            break;
        }

        if (authenticate_user(username, password))
        {
            authenticated = true;
            send_to_client(client_fd, "AUTHENTICATED");
            free(password);
            break;
        }

        send_to_client(client_fd, "ERROR: Authentication failed");
        free(password);
    }

    if (!authenticated)
    {
        LOG_ERROR("Authentication failed for user: %s", username);
        send_to_client(client_fd, "ERROR: Max login attempts");
        free(username);
        close(client_fd);
        return NULL;
    }

    // create pseudo-terminal
    struct winsize term_size = {
        .ws_row = 24,
        .ws_col = 80,
        .ws_xpixel = 0,
        .ws_ypixel = 0};

    child_pid = forkpty(&master_fd, NULL, NULL, &term_size);

    if (child_pid < 0)
    {
        LOG_ERROR("Failed to fork pseudo-terminal: %s", strerror(errno));
        send_to_client(client_fd, "ERROR: PTY creation failed");
        cleanup_and_close(client_fd, master_fd, child_pid);
        free(username);
        return NULL;
    }

    if (!child_pid)
    {
        // child process: drop privileges and execute shell
        if (!drop_privileges(username))
        {
            LOG_ERROR("Failed to drop privileges");
            exit(EXIT_FAILURE);
        }

        struct passwd *pw = getpwnam(username);
        if (!pw)
        {
            LOG_ERROR("Failed to get user info");
            exit(EXIT_FAILURE);
        }

        execl(pw->pw_shell, pw->pw_shell, NULL);

        // if we get here, exec failed
        LOG_ERROR("Failed to execute shell: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // parent process: relay data
    free(username); // don't need username anymore

    fd_set read_fds;
    char buffer[MAX_STRLEN];
    char cmd_buffer[MAX_STRLEN] = {0};
    size_t cmd_len = 0;

    while (1)
    {
        FD_ZERO(&read_fds);
        FD_SET(client_fd, &read_fds);
        FD_SET(master_fd, &read_fds);

        int max_fd = (client_fd > master_fd ? client_fd : master_fd) + 1;

        if (select(max_fd, &read_fds, NULL, NULL, NULL) < 0)
        {
            if (errno == EINTR)
                continue; // interrupted, retry

            LOG_ERROR("Select failed: %s", strerror(errno));
            break;
        }

        // client to PTY
        if (FD_ISSET(client_fd, &read_fds))
        {
            ssize_t bytes_read = safe_read(client_fd, buffer, sizeof(buffer));
            if (bytes_read <= 0)
            {
                if (bytes_read < 0)
                    LOG_ERROR("Error reading from client: %s", strerror(errno));
                break;
            }

            // write directly to master PTY - the client will handle line buffering
            if (safe_write(master_fd, buffer, bytes_read) < 0)
            {
                LOG_ERROR("Error writing to PTY: %s", strerror(errno));
                break;
            }
        }

        // PTY to client
        if (FD_ISSET(master_fd, &read_fds))
        {
            ssize_t bytes_read = read(master_fd, buffer, sizeof(buffer) - 1);

            if (bytes_read <= 0)
            {
                if (bytes_read < 0)
                    LOG_ERROR("Error reading from PTY: %s", strerror(errno));
                else
                    LOG_INFO("PTY closed connection");
                break;
            }

            buffer[bytes_read] = '\0';

            // send data directly to client
            if (safe_write(client_fd, buffer, bytes_read) < 0)
            {
                LOG_ERROR("Error writing to client: %s", strerror(errno));
                break;
            }
        }
    }

    cleanup_and_close(client_fd, master_fd, child_pid);
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        usage_error();
        return EXIT_FAILURE;
    }

    // parse port
    char *endptr;
    int port = strtol(argv[1], &endptr, 10);
    if (*endptr || port <= 0 || port > 65535)
    {
        LOG_ERROR("Invalid port number: %s", argv[1]);
        return EXIT_FAILURE;
    }

    // create socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        LOG_ERROR("Socket creation failed: %s", strerror(errno));
        return EXIT_FAILURE;
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        LOG_ERROR("Socket option setting failed: %s", strerror(errno));
        close(server_fd);
        return EXIT_FAILURE;
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        LOG_ERROR("Bind failed: %s", strerror(errno));
        close(server_fd);
        return EXIT_FAILURE;
    }

    if (listen(server_fd, BACKLOG) < 0)
    {
        LOG_ERROR("Listen failed: %s", strerror(errno));
        close(server_fd);
        return EXIT_FAILURE;
    }

    LOG_INFO("Server started on port %d", port);

    while (1)
    {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        char client_ip[INET_ADDRSTRLEN];

        long long client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0)
        {
            LOG_ERROR("Accept failed: %s", strerror(errno));
            continue;
        }

        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        LOG_INFO("New connection from %s:%d", client_ip, ntohs(client_addr.sin_port));

        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

        pthread_t client_thread;
        if (pthread_create(&client_thread, &attr, client_handler, (void *)client_fd) != 0)
        {
            LOG_ERROR("Thread creation failed: %s", strerror(errno));
            close(client_fd);
        }

        pthread_attr_destroy(&attr);
    }

    close(server_fd);
    return EXIT_SUCCESS;
}

static void usage_error(void)
{
    fprintf(stderr, "Usage: %s <port>\n", "server");
}