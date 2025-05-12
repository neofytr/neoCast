#include "release/neobuild.h"
#include <stdio.h>

int main(int argc, char **argv)
{
    neorebuild("neo.c", argv);
    neo_compile_to_object_file(GCC, "main.c", "main.o", NULL, false);
    neo_link(GCC, "main", NULL, false, "main.o");
    remove("main.o");
    return EXIT_SUCCESS;
}