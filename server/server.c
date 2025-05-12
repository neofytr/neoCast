#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_STRLEN 4096
#define BACKLOG 5

static void usage_error(void)
{
    fprintf(stderr, "[ERROR] -> Incorrect Usage\n");
    fprintf(stderr, "Correct Usage -> ./server port\n");
}

// function to receive data from client
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
            // connection closed by client
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

    // if we've read MAX_STRLEN without finding \r\n
    fprintf(stderr, "[ERROR] -> Message too long or missing terminator\n");
    free(buffer);
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
    if (*endptr)
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
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        // accept client connection
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0)
        {
            fprintf(stderr, "[ERROR] -> Failed to accept connection: %s\n", strerror(errno));
            continue;
        }

        // get client's IP address
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
        printf("New connection from %s:%d\n", client_ip, ntohs(client_addr.sin_port));

        // receive hello message
        char *hello_msg = receive_from_client(client_fd);
        if (!hello_msg)
        {
            close(client_fd);
            continue;
        }

        // receive username
        char *username = receive_from_client(client_fd);
        if (!username)
        {
            free(hello_msg);
            close(client_fd);
            continue;
        }

        // display the received information
        printf("Received from client - Message: %s, Username: %s\n", hello_msg, username);

        // cleanup
        free(hello_msg);
        free(username);
        close(client_fd);
    }

    // close the server socket (this will never be reached in the current implementation)
    close(server_fd);
    return EXIT_SUCCESS;
}