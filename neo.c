#include "release/neobuild.h"
#include <stdio.h>

int main(int argc, char **argv)
{
    neorebuild("neo.c", argv);
    return EXIT_SUCCESS;
}