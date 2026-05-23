#include <stdio.h>

// This attribute forces this function to run as soon as the library is loaded
void __attribute__((constructor)) init() {
    printf("[+] Hello from expected!\n");
}

void custom_function() {
    printf("[+] custom_function called\n");
}

