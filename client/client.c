#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h> // for inet_pton
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MAX_STRLEN (4096 + 1)
#define LOOPBACK "127.0.0.1"

static void usage_error(void)
{
    fprintf(stderr, "[ERROR] -> Incorrect Usage\n");
    fprintf(stderr, "Correct Usage -> ./client username@ipaddress port\n");
}

static void send_to_server(int server_fd, const char *msg)
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
            return;
        }
        sent += bytes_sent;
    }
}

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        usage_error();
        return EXIT_FAILURE;
    }

    char user[MAX_STRLEN];
    char ip_addr[INET_ADDRSTRLEN];
    char *ptr = argv[1];
    int index = 0;

    // extract username
    while (*ptr != '@' && *ptr != '\0')
    {
        user[index++] = *ptr++;
    }
    user[index] = '\0';

    // check if we found the '@' symbol
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
        ip_addr[index++] = *ptr++;
    }
    ip_addr[index] = '\0';

    if (!strcmp(ip_addr, "localhost"))
    {
        strcpy(ip_addr, LOOPBACK);
    }

    char *endptr;
    int port = strtol(argv[2], &endptr, 10);
    if (*endptr)
    {
        fprintf(stderr, "[ERROR] -> Invalid port number: %s\n", argv[2]);
        return EXIT_FAILURE;
    }

    struct sockaddr_in server;
    memset(&server, 0, sizeof(struct sockaddr_in));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    if (inet_pton(AF_INET, ip_addr, &server.sin_addr) != 1)
    {
        fprintf(stderr, "[ERROR] -> Invalid IPv4 %s: %s\n", ip_addr, strerror(errno));
        return EXIT_FAILURE;
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        fprintf(stderr, "[ERROR] -> Couldn't create a socket: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    if (connect(server_fd, (struct sockaddr *)&server, sizeof(struct sockaddr_in)) < 0)
    {
        fprintf(stderr, "[ERROR] -> Couldn't connect to the server IPv4: %s Port: %d -> %s\n",
                ip_addr, port, strerror(errno));
        close(server_fd);
        return EXIT_FAILURE;
    }

    // send hello message followed by username
    send_to_server(server_fd, "HELLO\r\n");
    send_to_server(server_fd, user);
    send_to_server(server_fd, "\r\n");

    printf("Connected to server. Sent username: %s\n", user);

    // clean up
    close(server_fd);
    return EXIT_SUCCESS;
}