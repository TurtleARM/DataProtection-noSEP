/*
 * arch.h - Code to deal with different architectures.
 *
 * Copyright (c) 2014 Samuel Groß
 * Copyright (c) 2016-2017 Siguza
 */

#ifndef ARCH_H
#define ARCH_H

#include <TargetConditionals.h> // TARGET_OS_IPHONE
#include <mach-o/loader.h>      // mach_header, mach_header_64, segment_command, segment_command_64

#include <CoreFoundation/CoreFoundation.h> // kCFCoreFoundationVersionNumber

#ifndef TARGET_OS_IPHONE
#   error "TARGET_OS_IPHONE not defined"
#endif

#if !(TARGET_OS_IPHONE)
#   define TARGET_MACOS
#endif

// 1199 = kCFCoreFoundationVersionNumber_iOS_8_x_Max or kCFCoreFoundationVersionNumber10_10_Max
#define HAVE_TAGGED_REGIONS (kCFCoreFoundationVersionNumber <= 1199)

#if __LP64__
#   ifdef TARGET_MACOS
#       define IMAGE_OFFSET 0
#       define MACH_TYPE CPU_TYPE_X86_64
#   else
#       define IMAGE_OFFSET 0x2000
#       define MACH_TYPE CPU_TYPE_ARM64
#   endif
#   define ADDR "%016lx"
#   define SIZE "%lu"
#   define MACH_HEADER_MAGIC MH_MAGIC_64
#   define MACH_LC_SEGMENT LC_SEGMENT_64
#   define MACH_LC_SEGMENT_NAME "LC_SEGMENT_64"
#   define KERNEL_SPACE 0x8000000000000000
    typedef struct mach_header_64 mach_hdr_t;
    typedef struct segment_command_64 mach_seg_t;
    typedef struct section_64 mach_sec_t;
#else
#   ifdef TARGET_MACOS
#       error "Unsupported architecture"
#   else
#       define IMAGE_OFFSET 0x1000
#       define MACH_TYPE CPU_TYPE_ARM
#   endif
#   define ADDR "%08x"
#   define SIZE "%u"
#   define MACH_HEADER_MAGIC MH_MAGIC
#   define MACH_LC_SEGMENT LC_SEGMENT
#   define MACH_LC_SEGMENT_NAME "LC_SEGMENT"
#   define KERNEL_SPACE 0x80000000
    typedef struct mach_header mach_hdr_t;
    typedef struct segment_command mach_seg_t;
    typedef struct section mach_sec_t;
#endif
typedef struct load_command mach_lc_t;

#endif
