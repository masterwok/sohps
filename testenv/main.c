#include <stdio.h>
#include <unistd.h>

extern void custom_function();

int main() {
    printf("[*] Running target binary (UID: %d, EUID: %d)...\n", getuid(), geteuid());
    custom_function();
    return 0;
}
