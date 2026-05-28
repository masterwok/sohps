#include <stdio.h>
#include <dlfcn.h>

int main() {
    void *h = dlopen("libtest.so", RTLD_NOW);
    if (!h) {
        fprintf(stderr, "Error: %s\n", dlerror());
        return 1;
    }
    printf("Success\n");
    return 0;
}
