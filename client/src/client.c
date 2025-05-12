#include "../inc/client.h"
#include <stdlib.h>
#include <stdio.h>

#include <arpa/inet.h> // for inet_pton
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>

#define MAX_STRLEN (4096 + 1)
#define LOOPBACK "127.0.0.1"

static void usage_error(void)
{
    fprintf(stderr, "[ERROR] -> Incorrect Usage\n");
    fprintf(stderr, "Correct Usage -> ./client <username>@<ip_address> <port>\n");
}

static void send_to_server(int server_fd, const char *msg)
{
    // use strlen to get the actual message length
    int size = strlen(msg);
    uintptr_t sent = 0;
    while (size > 0)
    {
        int bytes = write(server_fd, msg + sent, size);
        if (bytes < 0)
        {
            fprintf(stderr, "[ERROR] -> Failed to send message: %s\n", strerror(errno));
            return;
        }
        sent += bytes;
        size -= bytes;
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
    while (*ptr && *ptr != '@')
    {
        user[index++] = *ptr++;
    }
    user[index] = 0;

    // check if we found the @ symbol
    if (*ptr != '@')
    {
        fprintf(stderr, "[ERROR] -> Invalid format. Use <username>@<ip_address>\n");
        return EXIT_FAILURE;
    }

    // skip the @ symbol
    ptr++;

    // extract ip_address properly
    index = 0;
    while (*ptr)
    {
        ip_addr[index++] = *ptr++;
    }
    ip_addr[index] = 0;

    if (!strcmp(ip_addr, "localhost"))
    {
        strcpy(ip_addr, LOOPBACK);
    }

    char *endptr;
    int port = strtol(argv[2], &endptr, 10);

    if (*endptr)
    {
        fprintf(stderr, "Invalid port number: %s\n", argv[2]);
        return 1;
    }

    struct sockaddr_in server;
    memset((void *)&server, 0, sizeof(struct sockaddr_in));

    server.sin_family = AF_INET;   // set the family
    server.sin_port = htons(port); // use htons for network byte order

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

    // cast to struct sockaddr* and pass correct size
    if (connect(server_fd, (struct sockaddr *)&server, sizeof(server)) < 0)
    {
        fprintf(stderr, "[ERROR] -> Couldn't connect to the server IPv4: %s Port: %d -> %s\n", ip_addr, port, strerror(errno));
        close(server_fd);
        return EXIT_FAILURE;
    }

    // send a proper protocol message
    send_to_server(server_fd, "HELLO\n");
    send_to_server(server_fd, user);

    printf("[INFO] -> Connected to server at %s:%d as %s\n", ip_addr, port, user);

    // add a clean shutdown
    close(server_fd);
    return EXIT_SUCCESS;
}