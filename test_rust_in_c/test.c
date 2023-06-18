extern int add_numbers();
extern void hello_devworld();
// #include "librust_module.a";

#include <stdio.h>

int main(int argc, char *argv[]) {
	printf("\n%d\n",add_numbers(1,2));
    hello_devworld();
    return 0;
}