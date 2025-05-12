#include "buildsysdep/neobuild.h"
#include <stdlib.h>

int main(int argc, char **argv)
{
    neorebuild("neo.c", argv);
    if (argc > 1 && !strcmp(argv[1], "clean"))
    {
        remove("client_test");
        remove("server_test");
        return EXIT_SUCCESS;
    }

    neo_compile_to_object_file(GCC, "client/client.c", NULL, NULL, true);
    neo_compile_to_object_file(GCC, "server/server.c", NULL, NULL, true);
    neo_link(GCC, "client_test", NULL, true, "client/client.o");
    neo_link(GCC, "server_test", NULL, true, "server/server.o");
    remove("client/client.o");
    remove("server/server.o");

    return EXIT_SUCCESS;
}