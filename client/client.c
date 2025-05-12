#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include <arpa/inet.h> // for inet_pton
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <termios.h>
#include <fcntl.h>
#include <sys/select.h>

#define MAX_STRLEN (4096 + 1)
#define LOOPBACK "127.0.0.1"

// structure to hold connection details
typedef struct
{
    char username[MAX_STRLEN];
    char ip_addr[INET_ADDRSTRLEN];
    int port;
    int server_fd;
} ConnectionDetails;

// print usage instructions for incorrect command-line arguments
static void usage_error(void)
{
    fprintf(stderr, "[ERROR] -> Incorrect Usage\n");
    fprintf(stderr, "Correct Usage -> ./client username@ipaddress port\n");
}

// safely send data to server with error handling
static bool send_to_server(int server_fd, const char *msg)
{
    size_t size = strlen(msg);
    size_t sent = 0;
    ssize_t bytes_sent;

    while (sent < size)
    {
        bytes_sent = write(server_fd, msg + sent, size - sent);
        if (bytes_sent < 0)
        {
            fprintf(stderr, "[ERROR] -> Failed to send data: %s\n", strerror(errno));
            return false;
        }
        sent += bytes_sent;
    }

    // append carriage return and newline for protocol
    bytes_sent = write(server_fd, "\r\n", 2);
    return bytes_sent == 2;
}

// read server response with error handling
static char *receive_from_server(int server_fd)
{
    char *buffer = malloc(MAX_STRLEN);
    if (!buffer)
    {
        fprintf(stderr, "[ERROR] -> Memory allocation failed\n");
        return NULL;
    }

    size_t total_read = 0;
    ssize_t bytes_received;

    while (total_read < MAX_STRLEN - 1)
    {
        bytes_received = read(server_fd, buffer + total_read, 1);

        if (bytes_received < 0)
        {
            fprintf(stderr, "[ERROR] -> Failed to receive data: %s\n", strerror(errno));
            free(buffer);
            return NULL;
        }

        if (!bytes_received)
        {
            // connection closed by server
            fprintf(stderr, "[ERROR] -> Connection closed by server\n");
            free(buffer);
            return NULL;
        }

        total_read++;

        // check for termination sequence
        if (total_read >= 2 &&
            buffer[total_read - 2] == '\r' &&
            buffer[total_read - 1] == '\n')
        {
            // remove termination sequence
            buffer[total_read - 2] = '\0';
            return buffer;
        }
    }

    // message too long
    fprintf(stderr, "[ERROR] -> Server response too long\n");
    free(buffer);
    return NULL;
}

// read password securely without echoing
static char *read_password(const char *prompt)
{
    struct termios old_term, new_term;
    char *password = malloc(MAX_STRLEN);

    if (!password)
    {
        fprintf(stderr, "[ERROR] -> Memory allocation failed\n");
        return NULL;
    }

    // get the terminal attributes
    tcgetattr(STDIN_FILENO, &old_term);
    new_term = old_term;

    // disable echo
    new_term.c_lflag &= ~(ECHO | ICANON);
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);

    printf("%s", prompt);
    fflush(stdout);

    // read password
    if (fgets(password, MAX_STRLEN, stdin) == NULL)
    {
        fprintf(stderr, "\n[ERROR] -> Failed to read password\n");
        tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
        free(password);
        return NULL;
    }

    // restore terminal
    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);

    // remove newline
    size_t len = strlen(password);
    if (len > 0 && password[len - 1] == '\n')
    {
        password[len - 1] = '\0';
    }

    printf("\n");
    return password;
}

// interactive shell session
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

        // wait for activity on either stdin or server socket
        int activity = select(max_fd, &read_fds, NULL, NULL, NULL);
        if (activity < 0)
        {
            perror("[ERROR] -> select error");
            break;
        }

        // input from user to send to server
        if (FD_ISSET(STDIN_FILENO, &read_fds))
        {
            ssize_t bytes_read = read(STDIN_FILENO, buffer, sizeof(buffer) - 1);
            if (bytes_read <= 0)
                break;

            buffer[bytes_read] = '\0';
            if (!send_to_server(server_fd, buffer))
                break;
        }

        // response from server
        if (FD_ISSET(server_fd, &read_fds))
        {
            char *response = receive_from_server(server_fd);
            if (!response)
                break;

            // check for error codes
            if (!strncmp(response, "ERROR", 5))
            {
                fprintf(stderr, "Server Error: %s\n", response);
                free(response);
                break;
            }

            // print server response
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
        usage_error();
        return EXIT_FAILURE;
    }

    ConnectionDetails conn = {0};
    char *ptr = argv[1];
    int index = 0;

    // extract username
    while (*ptr != '@' && *ptr != '\0')
    {
        conn.username[index++] = *ptr++;
    }
    conn.username[index] = '\0';

    // check for '@' symbol
    if (*ptr != '@')
    {
        fprintf(stderr, "[ERROR] -> Invalid format: missing '@' symbol\n");
        usage_error();
        return EXIT_FAILURE;
    }

    // skip the '@' symbol
    ptr++;

    // extract IP address
    index = 0;
    while (*ptr != '\0')
    {
        conn.ip_addr[index++] = *ptr++;
    }
    conn.ip_addr[index] = '\0';

    // handle localhost
    if (!strcmp(conn.ip_addr, "localhost"))
    {
        strcpy(conn.ip_addr, LOOPBACK);
    }

    // parse port number
    char *endptr;
    conn.port = strtol(argv[2], &endptr, 10);
    if (*endptr || conn.port <= 0 || conn.port > 65535)
    {
        fprintf(stderr, "[ERROR] -> Invalid port number: %s\n", argv[2]);
        return EXIT_FAILURE;
    }

    // prepare server address
    struct sockaddr_in server;
    memset(&server, 0, sizeof(struct sockaddr_in));
    server.sin_family = AF_INET;
    server.sin_port = htons(conn.port);

    // convert IP address
    if (inet_pton(AF_INET, conn.ip_addr, &server.sin_addr) != 1)
    {
        fprintf(stderr, "[ERROR] -> Invalid IPv4 %s: %s\n", conn.ip_addr, strerror(errno));
        return EXIT_FAILURE;
    }

    // create socket
    conn.server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (conn.server_fd < 0)
    {
        fprintf(stderr, "[ERROR] -> Couldn't create a socket: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    // connect to server
    if (connect(conn.server_fd, (struct sockaddr *)&server, sizeof(struct sockaddr_in)) < 0)
    {
        fprintf(stderr, "[ERROR] -> Couldn't connect to the server IPv4: %s Port: %d -> %s\n",
                conn.ip_addr, conn.port, strerror(errno));
        close(conn.server_fd);
        return EXIT_FAILURE;
    }

    printf("Connected to server at %s:%d\n", conn.ip_addr, conn.port);

    // send username
    if (!send_to_server(conn.server_fd, conn.username))
    {
        close(conn.server_fd);
        return EXIT_FAILURE;
    }

    // authentication loop
    bool authenticated = false;
    for (int attempts = 0; attempts < 3; attempts++)
    {
        // prompt for password
        char *password = read_password("Enter password: ");
        if (!password)
        {
            close(conn.server_fd);
            return EXIT_FAILURE;
        }

        // send password
        if (!send_to_server(conn.server_fd, password))
        {
            free(password);
            close(conn.server_fd);
            return EXIT_FAILURE;
        }

        // receive server response
        char *response = receive_from_server(conn.server_fd);
        if (!response)
        {
            free(password);
            close(conn.server_fd);
            return EXIT_FAILURE;
        }

        // check if authentication was successful
        if (!strcmp(response, "VERIFIED"))
        {
            free(password);
            free(response);
            authenticated = true;
            break;
        }

        // print error and continue if not authenticated
        fprintf(stderr, "Authentication failed: %s\n", response);
        free(password);
        free(response);
    }

    // exit if authentication failed
    if (!authenticated)
    {
        fprintf(stderr, "Max login attempts reached\n");
        close(conn.server_fd);
        return EXIT_FAILURE;
    }

    // start interactive shell session
    int result = interactive_shell(conn.server_fd);

    // cleanup
    close(conn.server_fd);
    return result == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}