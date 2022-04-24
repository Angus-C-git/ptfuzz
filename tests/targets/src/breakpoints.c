/**
 * @file breakpoints.c
 * @author Angus C
 * @brief A dummy tracee program to test
 * setting and restoring breakpoints
 * @version 0.1
 * @date 2022-04-24
 *
 * @copyright Copyright (c) 2022
 *
 */
#include <stdio.h>
#include <stdlib.h>

// bloat   functions
int bp_1(void)
{
    printf("[>>] Breakpoint 1\n");
    return 0;
}

int bp_2(void)
{
    printf("[>>] Breakpoint 2\n");
    return 0;
}

int bp_3(void)
{
    printf("[>>] Breakpoint 3\n");
    return 0;
}

int bp_4(void)
{
    printf("[>>] Breakpoint 4\n");
    return 0;
}

int bp_5(void)
{
    printf("[>>] Breakpoint 5\n");
    return 0;
}

int bp_6(void)
{
    printf("[>>] Breakpoint 6\n");
    return 0;
}

int bp_7(void)
{
    printf("[>>] Breakpoint 7\n");
    return 0;
}

int bp_8(void)
{
    printf("[>>] Breakpoint 8\n");
    return 0;
}

int bp_9(void)
{
    printf("[>>] Breakpoint 9\n");
    return 0;
}

int bp_10(void)
{
    printf("[>>] Breakpoint 10\n");
    return 0;
}

int main()
{
    printf("[>>] tracee program started\n");

    // echo function manifest
    printf("[>>] tracee contains 10 functions to break on\n\n");
    printf("  * \n");
    printf("  | \n");
    printf("  ├── bp_1 \n");
    printf("  | \n");
    printf("  | \n");
    printf("  ├── bp_2 \n");
    printf("  | \n");
    printf("  | \n");
    printf("  ├── bp_3 \n");
    printf("  | \n");
    printf("  | \n");
    printf("  ├── bp_4 \n");
    printf("  | \n");
    printf("  | \n");
    printf("  ├── bp_5 \n");
    printf("  | \n");
    printf("  | \n");
    printf("  └── bp_6 \n\n");

    // run the functions
    bp_1();
    bp_2();
    bp_3();
    bp_4();
    bp_5();
    bp_6();

    // hang the tracee
    getchar();

    printf("[>>] tracee program finished\n");
    return 0;
}