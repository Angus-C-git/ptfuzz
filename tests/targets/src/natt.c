#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

void print_banner(void);
void select_device(void);

void print_banner()
{
    printf("\n");
    printf(" _   _    _  _____ _____  \n");
    printf("| \\ | |  / \\|_   _|_   _| \n");
    printf("|  \\| | / _ \\ | |   | |   \n");
    printf("| |\\  |/ ___ \\| |   | |   \n");
    printf("|_| \\_/_/   \\_\\_|   |_|   \n\n");
    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>\n\n\n");

    printf(":::::::::::: [NetworkAllTheThings (NATT) | Now with more things] :::::::::::: \n\n");
}

void menu()
{
    printf("(1) Network a coffee grinder\n");
    printf("(2) Network a kettle\n");
    printf("(3) Network a microwave\n");
    printf("(4) Network a toaster\n");
    printf("(5) Network a blender\n");
    printf("(6) Network a defuser\n");
    printf("(7) Network a washing machine running MIPS\n");
    printf("(8) Network a clock\n");
    printf("(9) Network a massaging recliner\n");
    printf("(10) Network a network\n");

    select_device();
}

/*
Vulnerable function
+ One of the devices will expose
  a buffer overflow vulnerability 
*/
void network_device(int device_key)
{
    uint16_t port;
    char ip[20];

    /* device specific fields */
    char location[101];
    char model_info[42];
    int protocol;

    switch (device_key)
    {
    case 1:
        printf("Networking Coffee Grinder ...\n");
        printf("Select mode:\n(1) TCP\n(2) UDP\n(3) telnet\n>_ ");
        scanf("%d", &protocol);
        break;
    case 2:
        printf("Networking Kettle ...\n");
        printf("Enter device location (bedroom, dog kennel, ...): ");
        fgets(location, 100, stdin);
        break;
    case 3:
        printf("Networking microwave ...\n");
        printf("Enter device location (bedroom, dog kennel, ...): ");
        fgets(location, 100, stdin);
        break;
    case 4:
        printf("Networking toaster ...\n");
        printf("Enter device location (bedroom, dog kennel, ...): ");
        fgets(location, 100, stdin);
        break;
    case 5:
        printf("Networking blender ...\n");
        printf("Enter device location (bedroom, dog kennel, ...): ");
        fgets(location, 100, stdin);
        break;
    case 6:
        printf("Networking defuser ...\n");
        printf("Enter device location (bedroom, dog kennel, ...): ");
        fgets(location, 100, stdin);
        break;
    case 7:
        printf("Newtworking Andrew T's washing machine ...\n");
        printf("Enter model details: \n");
        printf(">_ ");
        fgets(model_info, 0x142, stdin);
        printf("\n");
        printf("Select mode:\n(1) TCP\n(2) UDP\n");
        printf(">_ ");
        scanf("%d", &protocol);
        break;
    case 8:
        printf("Networking clock ...\n");
        printf("Enter device location (bedroom, dog kennel, ...): ");
        fgets(location, 100, stdin);
        break;
    case 9:
        printf("Networking Massaging Recliner ...\n");
        printf("Enter device location (bedroom, dog kennel, ...): ");
        fgets(location, 100, stdin);
        break;
    case 10:
        printf("Are you sure you want to network a network that seems a little odd?\n");
        getchar();
        printf("Um alright here we go ... \n");
        break;
    default:
        printf("Somehow we don't support that device \n");
        printf("NATT V2, compiled with libc-2.33.so");
        exit(0);
        break;
    }

    printf("Enter listening port: \n");
    printf(">_ ");
    scanf("%hd", &port);
    fgetc(stdin);
    printf("\n");
    printf("Enter device ip address: \n");
    printf(">_ ");
    fgets(ip, 20, stdin);
}

void select_device()
{
    char device_choice[4];
    int device;
    printf("\n");
    printf("Enter your device (1-10): \n");
    printf(">_ ");
    fgets(device_choice, 3, stdin);

    device = atoi(device_choice);
    // scanf("%d", &device);
    network_device(device);
}

int main(int argc, char const *argv[])
{
    print_banner();
    fflush(stdout);
    fflush(stdin);
    menu();
    // // printf("Press any key to continue...\n");
    // // fgetc(stdin);
    // select_device();

    printf("\nDevice setup!\n\n");
    printf(">>> Thanks for using NATT\n");

    return 0;
}