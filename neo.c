#include "buildsysdep/neobuild.h"
#include <stdlib.h>

int main(int argc, char **argv)
{
    neorebuild("neo.c", argv);
    neo_compile_to_object_file(GCC, "main.c", NULL, NULL, false);
    neo_link(GCC, "main", NULL, false, "main.o");
    remove("./main.o");
    return EXIT_SUCCESS;
}