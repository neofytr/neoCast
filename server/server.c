#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <pty.h>
#include <sys/select.h>
#include <sys/wait.h>

#include <stdbool.h>
#include <shadow.h>
#include <crypt.h>

#include <pwd.h>
#include <sys/types.h>
#include <signal.h>

// Maximum length for input strings
#define MAX_STRLEN 4096
// Maximum number of login attempts
#define MAX_LOGIN_ATTEMPTS 3
// Number of connections the server can queue
#define BACKLOG 5

// Function declarations
static void usage_error(void);
static char *receive_from_client(int client_fd);
static bool authenticate_user(const char *username, const char *password);
static bool drop_privileges(const char *username);
static void send_to_client(int client_fd, const char *msg);
void *client_handler(void *arg);
static void cleanup_and_close(int client_fd, int master_fd, pid_t child_pid, const char *username);

// print usage instructions for incorrect command-line arguments
static void usage_error(void)
{
    fprintf(stderr, "[ERROR] -> Incorrect Usage\n");
    fprintf(stderr, "Correct Usage -> ./server port\n");
}

// receive data from client with proper error handling and termination detection
static char *receive_from_client(int client_fd)
{
    char *buffer = malloc(MAX_STRLEN + 1);
    if (!buffer)
    {
        fprintf(stderr, "[ERROR] -> Failed to allocate memory\n");
        return NULL;
    }

    size_t total_read = 0;
    ssize_t bytes_received;

    while (total_read < MAX_STRLEN)
    {
        bytes_received = read(client_fd, buffer + total_read, 1);

        if (bytes_received < 0)
        {
            fprintf(stderr, "[ERROR] -> Failed to receive data: %s\n", strerror(errno));
            free(buffer);
            return NULL;
        }

        if (!bytes_received)
        {
            // Connection closed by client
            fprintf(stderr, "[ERROR] -> Connection closed by client\n");
            free(buffer);
            return NULL;
        }

        total_read++;

        // check if we've received the termination sequence \r\n
        if (total_read >= 2 &&
            buffer[total_read - 2] == '\r' &&
            buffer[total_read - 1] == '\n')
        {
            // remove the \r\n terminator
            buffer[total_read - 2] = '\0';
            return buffer;
        }
    }

    // we've read MAX_STRLEN without finding \r\n
    fprintf(stderr, "[ERROR] -> Message too long or missing terminator\n");
    free(buffer);
    return NULL;
}

// authenticate user by comparing hashed password from shadow file
static bool authenticate_user(const char *username, const char *password)
{
    // get the user's shadow entry (which has the hashed password)
    struct spwd *shadow_entry = getspnam(username);
    if (!shadow_entry)
    {
        fprintf(stderr, "[ERROR] -> User not found in shadow file\n");
        return false;
    }

    // hash the provided password using the same salt from shadow_entry
    char *encrypted = crypt(password, shadow_entry->sp_pwdp);

    // compare the new hash with the stored hash
    return encrypted && !strcmp(encrypted, shadow_entry->sp_pwdp);
}

// drop privileges to the specified user
static bool drop_privileges(const char *username)
{
    // get the passwd entry for the given username
    struct passwd *pw = getpwnam(username);
    if (!pw)
    {
        fprintf(stderr, "[ERROR] -> User not found in passwd file\n");
        return false;
    }

    // change to the user's home directory
    if (chdir(pw->pw_dir) != 0)
    {
        fprintf(stderr, "[ERROR] -> Failed to change directory to user's home: %s\n", strerror(errno));
        return false;
    }

    // set the group id to the user's group id
    if (setgid(pw->pw_gid) != 0)
    {
        fprintf(stderr, "[ERROR] -> Failed to set group id: %s\n", strerror(errno));
        return false;
    }

    // set the user id to the user's id
    if (setuid(pw->pw_uid) != 0)
    {
        fprintf(stderr, "[ERROR] -> Failed to set user id: %s\n", strerror(errno));
        return false;
    }

    return true;
}

// send a message to the client with error handling
static void send_to_client(int client_fd, const char *msg)
{
    size_t size = strlen(msg);
    size_t sent = 0;
    ssize_t bytes_sent;

    while (sent < size)
    {
        bytes_sent = write(client_fd, msg + sent, size - sent);
        if (bytes_sent < 0)
        {
            fprintf(stderr, "[ERROR] -> Failed to send data: %s\n", strerror(errno));
            return;
        }
        sent += bytes_sent;
    }
}

// cleanup function to close file descriptors and kill child process
static void cleanup_and_close(int client_fd, int master_fd, pid_t child_pid, const char *username)
{
    // kill the child process if it exists
    if (child_pid > 0)
    {
        kill(child_pid, SIGTERM);
        // wait for the child to terminate
        waitpid(child_pid, NULL, 0);
    }

    // close file descriptors
    if (master_fd >= 0)
    {
        close(master_fd);
    }
    if (client_fd >= 0)
    {
        close(client_fd);
    }

    // free username if it exists
    if (username)
    {
        free((char *)username);
    }
}

// handle individual client connections
void *client_handler(void *arg)
{
    long long client_fd = (long long)arg;
    const char *username = NULL;
    int master_fd = -1;
    pid_t child_pid = -1;

    // receive username
    username = receive_from_client(client_fd);
    if (!username)
    {
        send_to_client(client_fd, "ERROR 100\r\n"); // couldn't read username
        close(client_fd);
        return NULL;
    }

    // authenticate
    bool verified = false;
    for (int tries = 1; tries <= MAX_LOGIN_ATTEMPTS; tries++)
    {
        const char *password = receive_from_client(client_fd);
        if (!password)
        {
            send_to_client(client_fd, "ERROR 101\r\n"); // couldn't read password
            cleanup_and_close(client_fd, master_fd, child_pid, username);
            return NULL;
        }

        if (!authenticate_user(username, password))
        {
            send_to_client(client_fd, "ERROR 102\r\n"); // invalid password
            free((char *)password);
        }
        else
        {
            verified = true;
            free((char *)password);
            break;
        }
    }

    if (!verified)
    {
        send_to_client(client_fd, "ERROR 103\r\n"); // all login attempts exhausted
        cleanup_and_close(client_fd, master_fd, child_pid, username);
        return NULL;
    }

    // fork a pseudo-terminal
    child_pid = forkpty(&master_fd, NULL, NULL, NULL);

    if (child_pid < 0)
    {
        fprintf(stderr, "[ERROR] -> Couldn't fork a pseudo-terminal: %s\n", strerror(errno));
        send_to_client(client_fd, "ERROR 104\r\n");
        cleanup_and_close(client_fd, master_fd, child_pid, username);
        return NULL;
    }

    if (child_pid == 0)
    {
        // child process (slave)
        // drop privileges to the authenticated user
        if (!drop_privileges(username))
        {
            send_to_client(client_fd, "ERROR 105\r\n"); // Couldn't drop privileges
            exit(EXIT_FAILURE);
        }

        // get user's login shell
        struct passwd *pw = getpwnam(username);
        if (!pw)
        {
            send_to_client(client_fd, "ERROR 106\r\n"); // Couldn't get user's login shell
            exit(EXIT_FAILURE);
        }

        // execute user's login shell
        execl(pw->pw_shell, pw->pw_shell, "--login", (char *)NULL);

        // will reach here only if execl fails
        send_to_client(client_fd, "ERROR 107\r\n");
        exit(EXIT_FAILURE);
    }

    // parent process: relay data between client and shell
    fd_set fds;
    while (true)
    {
        FD_ZERO(&fds);
        FD_SET(client_fd, &fds);
        FD_SET(master_fd, &fds);
        int maxfd = (client_fd > master_fd ? client_fd : master_fd) + 1;

        int ret = select(maxfd, &fds, NULL, NULL, NULL);
        if (ret < 0)
        {
            fprintf(stderr, "[ERROR] -> select call failed: %s\n", strerror(errno));
            send_to_client(client_fd, "ERROR 108\r\n");
            break;
        }

        // client -> PTY
        if (FD_ISSET(client_fd, &fds))
        {
            const char *msg = receive_from_client(client_fd);
            if (msg)
            {
                write(master_fd, msg, strlen(msg));
                write(master_fd, "\n", 1);
                free((char *)msg);
            }
            else
            {
                break;
            }
        }

        // PTY -> Client
        if (FD_ISSET(master_fd, &fds))
        {
            char buffer[MAX_STRLEN];
            ssize_t bytes_read = read(master_fd, buffer, sizeof(buffer) - 1);
            if (bytes_read > 0)
            {
                buffer[bytes_read] = '\0';
                send_to_client(client_fd, buffer);
            }
            else
            {
                break;
            }
        }
    }

    cleanup_and_close(client_fd, master_fd, child_pid, username);
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        usage_error();
        return EXIT_FAILURE;
    }

    // parse port number
    char *endptr;
    int port = strtol(argv[1], &endptr, 10);
    if (*endptr || port <= 0 || port > 65535)
    {
        fprintf(stderr, "[ERROR] -> Invalid port number: %s\n", argv[1]);
        return EXIT_FAILURE;
    }

    // create socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        fprintf(stderr, "[ERROR] -> Couldn't create a socket: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    // set socket option to reuse address
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        fprintf(stderr, "[ERROR] -> Failed to set socket options: %s\n", strerror(errno));
        close(server_fd);
        return EXIT_FAILURE;
    }

    // prepare server address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    // bind socket to address
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        fprintf(stderr, "[ERROR] -> Failed to bind to port %d: %s\n", port, strerror(errno));
        close(server_fd);
        return EXIT_FAILURE;
    }

    // listen for connections
    if (listen(server_fd, BACKLOG) < 0)
    {
        fprintf(stderr, "[ERROR] -> Failed to listen: %s\n", strerror(errno));
        close(server_fd);
        return EXIT_FAILURE;
    }

    printf("Server started. Listening on port %d...\n", port);

    while (1)
    {
        socklen_t client_len = sizeof(struct sockaddr_in);
        struct sockaddr_in client_addr;

        // accept client connection
        long long client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0)
        {
            fprintf(stderr, "[ERROR] -> Failed to accept connection: %s\n", strerror(errno));
            continue;
        }

        // create a new thread to handle the new client
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

        pthread_t client_thread;
        if (pthread_create(&client_thread, &attr, client_handler, (void *)client_fd) != 0)
        {
            fprintf(stderr, "[ERROR] -> Failed to create client thread\n");
            close(client_fd);
        }

        pthread_attr_destroy(&attr);

        // get client's IP address (optional, can be used for logging)
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    }

    // close the server socket (this will never be reached in the current implementation)
    close(server_fd);
    return EXIT_SUCCESS;
}