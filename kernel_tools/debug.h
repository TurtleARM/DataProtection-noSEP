/*
 * debug.h - Well, debugging.
 *
 * Copyright (c) 2016 Siguza
 */

#ifndef DEBUG_H
#define DEBUG_H

#include <stdbool.h>            // bool
#include <stdio.h>              // fprintf, stderr
#include <unistd.h>             // usleep

#define BUGTRACKER_URL "https://github.com/Siguza/ios-kern-utils/issues/new"

#define DEBUG(str, args...) \
do \
{ \
    if(verbose) \
    { \
        fprintf(stderr, "[DEBUG] " str " [" __FILE__ ":%u]\n", ##args, __LINE__); \
    } \
    if(slow) \
    { \
        usleep(100); \
    } \
} while(0)

extern bool verbose;
extern bool slow;

#endif
