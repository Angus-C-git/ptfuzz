/**
 * @file tracee.c
 * @author Angus C
 * @brief A dummy tracee program to test
 * the ptrace wrapper module, ptfuzz and 
 * general coverage oprations.
 * @version 0.1
 * @date 2021-11-28
 * 
 * @copyright Copyright (c) 2021
 * 
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

// bloat functions
void selected_function(void)
{
    printf("[>>] Representing new code path\n");
}

void simple_syscall(void)
{
    printf("[>>] simple syscall\n");
    sleep(5);
}

void simple_syscall_with_args(int arg1, int arg2)
{
    printf("[>>] simple syscall with args\n");
    sleep(1);
}

// pick a random number to seed a decision
int random_decision(void)
{
    return rand() % 2;
}

// function which prints diffrent
// things based on random decision
void print_decision()
{

    if (random_decision())
    {
        printf("[>>] Function coverage 1/2\n");
    }
    else
    {
        printf("[>>] Function coverage 2/2\n");
        selected_function();
    }
}

int main(int argc, char *argv[])
{
    printf("[>>] tracee program started\n");
    // seed generator
    srand(time(NULL));

    // echo function manifest
    printf("[>>] tracee contains 6 functions\n\n");
    printf("  * \n");
    printf("  | \n");
    printf("  ├── simple_syscall \n");
    printf("  | \n");
    printf("  | \n");
    printf("  ├── simple_syscall_with_args \n");
    printf("  | \n");
    printf("  | \n");
    printf("  ├── print_decision \n");
    printf("  | \n");
    printf("  | \n");
    printf("  ├── random_decision \n");
    printf("  | \n");
    printf("  | \n");
    printf("  ├── selected_function \n");
    printf("  | \n");
    printf("  | \n");
    printf("  └── main \n\n");

    // run the functions
    simple_syscall();
    simple_syscall_with_args(1, 2);
    print_decision();

    printf("[>>] tracee program finished\n");
    return 0;
}