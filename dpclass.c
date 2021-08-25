#include <sys/fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define F_GETPROTECTIONCLASS 63
#define F_SETPROTECTIONCLASS 64

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: %s {get/set} filename [dpclass]\n", argv[0]);
        return 0;
    }
    int fd = open(argv[2], O_RDWR);
    if (fd == 0) {
        printf("Error opening file\n");
        exit(0);
    }
    if (strcmp(argv[1], "get") == 0) {
        int dpclass = fcntl(fd, F_GETPROTECTIONCLASS);
        printf("%s DP Class = %d\n", argv[2], dpclass);
    } else if (strcmp(argv[1], "set") == 0) {
        int dpclass = atoi(argv[3]);
        fcntl(fd, F_SETPROTECTIONCLASS, dpclass);
    }
    return 0;
}