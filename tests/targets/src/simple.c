#include <stdio.h>

void simple(void)
{
    printf("🔥🔥🔥🔥\n");
}

/**
 * @brief a simple program that
 *       performs arbitrary operations
 *      on the stack with IO to test breakpoints
 * 
 * @return int 
 */
int main()
{
    printf("X ----------- Simple ----------- X\n");
    int a = 1;
    int b = 2;

    // add
    a += b;
    printf("%d + %d = %d\n", a, b, a);
    scanf("> %d", &a);
    // echo
    printf("%d\n", a);

    simple();

    return 0;
}