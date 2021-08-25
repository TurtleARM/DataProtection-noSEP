/*
 * libkern.c - Everything that touches the kernel.
 *
 * Copyright (c) 2014 Samuel Groß
 * Copyright (c) 2016-2017 Siguza
 */

#include <dlfcn.h>              // RTLD_*, dl*
#include <limits.h>             // UINT_MAX
#include <stdio.h>              // fprintf, snprintf
#include <stdlib.h>             // free, malloc, random, srandom
#include <string.h>             // memmem
#include <time.h>               // time

#include <mach/mach.h>          // Everything mach
#include <mach-o/loader.h>      // MH_EXECUTE
#include <mach-o/nlist.h>       // struct nlist_64
#include <sys/mman.h>           // mmap, munmap, MAP_FAILED
#include <sys/stat.h>           // fstat, struct stat
#include <sys/syscall.h>        // syscall

#include "arch.h"               // TARGET_MACOS, IMAGE_OFFSET, MACH_TYPE, MACH_HEADER_MAGIC, mach_hdr_t
#include "debug.h"              // DEBUG
#include "mach-o.h"             // CMD_ITERATE

#include "libkern.h"

#define MAX_CHUNK_SIZE 0xFFF /* MIG limitation */

#define VERIFY_PORT(port, ret) \
do \
{ \
    if(MACH_PORT_VALID(port)) \
    { \
        if(ret == KERN_SUCCESS) \
        { \
            DEBUG("Success!"); \
        } \
        else \
        { \
            DEBUG("Got a valid port, but return value is 0x%08x (%s)", ret, mach_error_string(ret)); \
            ret = KERN_SUCCESS; \
        } \
    } \
    else \
    { \
        if(ret == KERN_SUCCESS) \
        { \
            DEBUG("Returned success, but port is invalid (0x%08x)", port); \
            ret = KERN_FAILURE; \
        } \
        else \
        { \
            DEBUG("Failure. Port: 0x%08x, return value: 0x%08x (%s)", port, ret, mach_error_string(ret)); \
        } \
    } \
} while(0)

#define VERIFY_TASK(task, ret) \
do \
{ \
    if(ret == KERN_SUCCESS) \
    { \
        DEBUG("Checking if port is restricted..."); \
        mach_port_array_t __arr; \
        mach_msg_type_number_t __num; \
        ret = mach_ports_lookup(task, &__arr, &__num); \
        if(ret == KERN_SUCCESS) \
        { \
            task_t __self = mach_task_self(); \
            for(size_t __i = 0; __i < __num; ++__i) \
            { \
                mach_port_deallocate(__self, __arr[__i]); \
            } \
        } \
        else \
        { \
            DEBUG("Failure: task port 0x%08x is restricted.", task); \
            ret = KERN_NO_ACCESS; \
        } \
    } \
} while(0)

kern_return_t get_kernel_task(task_t *task)
{
    static task_t kernel_task = MACH_PORT_NULL;
    static bool initialized = false;
    if(!initialized)
    {
        DEBUG("Getting kernel task...");
        kern_return_t ret;
        kernel_task = MACH_PORT_NULL;
        host_t host = mach_host_self();

        // Try common workaround first
        DEBUG("Trying host_get_special_port(4)...");
        ret = host_get_special_port(host, HOST_LOCAL_NODE, 4, &kernel_task);
        VERIFY_PORT(kernel_task, ret);
        VERIFY_TASK(kernel_task, ret);

        if(ret != KERN_SUCCESS)
        {
            kernel_task = MACH_PORT_NULL;
#ifdef TARGET_MACOS
            // Huge props to Jonathan Levin for this method!
            // Who needs task_for_pid anyway? :P
            // ...or "needed", as of mid-Sierra. :/
            DEBUG("Trying processor_set_tasks()...");
            mach_port_t name = MACH_PORT_NULL,
                        priv = MACH_PORT_NULL;
            DEBUG("Getting default processor set name port...");
            ret = processor_set_default(host, &name);
            VERIFY_PORT(name, ret);
            if(ret == KERN_SUCCESS)
            {
                DEBUG("Getting default processor set priv port...");
                ret = host_processor_set_priv(host, name, &priv);
                VERIFY_PORT(priv, ret);
                if(ret == KERN_SUCCESS)
                {
                    DEBUG("Getting processor tasks...");
                    task_array_t tasks;
                    mach_msg_type_number_t num;
                    ret = processor_set_tasks(priv, &tasks, &num);
                    if(ret != KERN_SUCCESS)
                    {
                        DEBUG("Failed: %s", mach_error_string(ret));
                    }
                    else
                    {
                        DEBUG("Got %u tasks, looking for kernel task...", num);
                        for(size_t i = 0; i < num; ++i)
                        {
                            int pid = 0;
                            ret = pid_for_task(tasks[i], &pid);
                            if(ret != KERN_SUCCESS)
                            {
                                DEBUG("Failed to get pid for task %lu (%08x): %s", i, tasks[i], mach_error_string(ret));
                                break;
                            }
                            else if(pid == 0)
                            {
                                kernel_task = tasks[i];
                                break;
                            }
                        }
                        if(kernel_task == MACH_PORT_NULL)
                        {
                            DEBUG("Kernel task is not in set.");
                            ret = KERN_FAILURE;
                        }
                    }
                }
            }
#else
            DEBUG("Trying task_for_pid(0)...");
            ret = task_for_pid(mach_task_self(), 0, &kernel_task);
            VERIFY_PORT(kernel_task, ret);
#endif
        }
        VERIFY_TASK(kernel_task, ret);

        if(ret != KERN_SUCCESS)
        {
            DEBUG("Returning failure.");
            return ret;
        }
        DEBUG("Success, caching returned port.");
        initialized = true;
        DEBUG("kernel_task = 0x%08x", kernel_task);
    }
    *task = kernel_task;
    return KERN_SUCCESS;
}

// Kernel Base: This is a long story.
//
// Obtaining the kernel slide/base address is non-trivial, even with access to
// the kernel task port. Using the vm_region_* APIs, however, one can iterate
// over its memory regions, which provides a starting point. Additionally, there
// is a special region (I call it the "base region"), within which the kernel is
// located.
//
//
// Some history:
//
// In Saelo's original code (working up to and including iOS 7), the base region
// would be uniquely identified by being larger than 1 GB. The kernel had a
// simple offset from the region's base address of 0x1000 bytes on 32-bit, and
// 0x2000 bytes on 64-bit.
//
// With iOS 8, the property of being larger than 1GB was no longer unique.
// Additionally, one had to check for ---/--- access permissions, which would
// again uniquely identify the base region. The kernel offset from its base
// address remained the same.
//
// With iOS 9, the kernel's offset from the region's base address was doubled
// for most (but seemingly not all) devices. I simply checked both 0x1000 and
// 0x2000 for 32-bit and 0x2000 and 0x4000 for 64-bit.
//
// Somewhere between iOS 9.0 and 9.1, the kernel started not having a fixed
// offset from the region's base address anymore. In addition to the fixed
// offset, it could have a multiple of 0x100000 added to its address, seemingly
// uncorrelated to the region's base address, as if it had an additional KASLR
// slide applied within the region. Also, the kernel's offset from the region's
// base address could be much larger than the kernel itself.
// I worked around this by first locating the base region, checking for the
// Mach-O magic, and simply adding 0x100000 to the address until I found it.
//
// With iOS 10 (and seemingly even 9 on some devices), the base address
// identification was no longer sufficient, as another null mapping of 64GB size
// had popped up. So in addition to the other two, I added the criterium of a
// size smaller than 16GB.
// In addition to that, the part of the base region between its base address and
// the kernel base does no longer have to be mapped (that is, it's still part of
// the memory region, but trying to access it will cause a panic). This
// completely broke my workaround for iOS 9, and it's also the reason why both
// nonceEnabler and nvram_patcher don't work reliably. It's still possible to
// get it to work through luck, but that chance is pretty small.
//
//
// Current implementation:
//
// The base region still exists, still contains the kernel, and is still
// uniquely identifiable, but more information is required before one should
// attempt to access it. This "more information" can only be obtained from
// other memory regions.
// Now, kernel heap allocations larger than two page sizes go to either the
// kalloc_map or the kernel_map rather than zalloc, meaning they will directly
// pop up on the list of memory regions, and be identifiable by having a
// user_tag of VM_KERN_MEMORY_LIBKERN.
//
// So the current idea is to find a size of which no allocation with user_tag
// VM_KERN_MEMORY_LIBKERN exists, and to subsequently make such an allocation,
// which will then be uniquely identifiable. The allocation further incorporates
// OSObjects, which will contain vtable pointers, which are valid pointers to
// the kernel's base region. From there, we simply search backwards until we
// find the kernel header.


// true = continue, false = abort
typedef bool (*kernel_region_callback_t) (vm_address_t, vm_size_t, vm_region_submap_info_data_64_t*, void*);

// true = success, false = failure
static bool foreach_kernel_region(kernel_region_callback_t cb, void *arg)
{
    DEBUG("Looping over kernel memory regions...");
    task_t kernel_task;
    if(get_kernel_task(&kernel_task) != KERN_SUCCESS)
    {
        return false;
    }

    vm_region_submap_info_data_64_t info;
    vm_size_t size;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    unsigned int depth;
    for(vm_address_t addr = 0; 1; addr += size)
    {
        DEBUG("Searching for next region at " ADDR "...", addr);
        depth = UINT_MAX;
        if(vm_region_recurse_64(kernel_task, &addr, &size, &depth, (vm_region_info_t)&info, &info_count) != KERN_SUCCESS)
        {
            break;
        }
        if(!cb(addr, size, &info, arg))
        {
            return false;
        }
    }

    return true;
}

typedef struct
{
    char magic[16];
    uint32_t segoff;
    uint32_t nsegs;
    uint32_t _unused32[2];
    uint64_t _unused64[5];
    uint64_t localoff;
    uint64_t nlocals;
} dysc_hdr_t;

typedef struct
{
    uint64_t addr;
    uint64_t size;
    uint64_t fileoff;
    vm_prot_t maxprot;
    vm_prot_t initprot;
} dysc_seg_t;

typedef struct
{
    uint32_t nlistOffset;
    uint32_t nlistCount;
    uint32_t stringsOffset;
    uint32_t stringsSize;
    uint32_t entriesOffset;
    uint32_t entriesCount;
} dysc_local_info_t;

typedef struct
{
    uint32_t dylibOffset;
    uint32_t nlistStartIndex;
    uint32_t nlistCount;
} dysc_local_entry_t;

enum
{
    kOSSerializeDictionary      = 0x01000000U,
    kOSSerializeArray           = 0x02000000U,
    kOSSerializeSet             = 0x03000000U,
    kOSSerializeNumber          = 0x04000000U,
    kOSSerializeSymbol          = 0x08000000U,
    kOSSerializeString          = 0x09000000U,
    kOSSerializeData            = 0x0a000000U,
    kOSSerializeBoolean         = 0x0b000000U,
    kOSSerializeObject          = 0x0c000000U,

    kOSSerializeTypeMask        = 0x7F000000U,
    kOSSerializeDataMask        = 0x00FFFFFFU,

    kOSSerializeEndCollection   = 0x80000000U,

    kOSSerializeMagic           = 0x000000d3U,
};

#define IOKIT_PATH "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit"

static mach_port_t libkern_allocate(vm_size_t size)
{
    mach_port_t port = MACH_PORT_NULL;
    void *IOKit = NULL;
#if defined(__LP64__) && !defined(TARGET_MACOS)
    int fd = 0;
    void *cache = NULL;
    struct stat s = {0};
#endif

    mach_port_t master = MACH_PORT_NULL;
    kern_return_t ret = host_get_io_master(mach_host_self(), &master);
    if(ret != KERN_SUCCESS)
    {
        DEBUG("Failed to get IOKit master port: %s", mach_error_string(ret));
        goto out;
    }

    IOKit = dlopen(IOKIT_PATH, RTLD_LAZY | RTLD_LOCAL | RTLD_FIRST);
    if(IOKit == NULL)
    {
        DEBUG("Failed to load IOKit.");
        goto out;
    }

    // Ye olde MIG
    kern_return_t (*io_service_add_notification_ool)(mach_port_t, const char*, void*, mach_msg_type_number_t, mach_port_t, void*, mach_msg_type_number_t, kern_return_t*, mach_port_t*) = NULL;
#ifdef __LP64__
    // 64-bit IOKit doesn't export the MIG function, but still has a symbol for it.
    // We go through all this trouble rather than statically linking against MIG because
    // that becomes incompatible every now and then, while IOKit is always up to date.

    char *IOServiceOpen = dlsym(IOKit, "IOServiceOpen"); // char for pointer arithmetic
    if(IOServiceOpen == NULL)
    {
        DEBUG("Failed to find IOServiceOpen.");
        goto out;
    }

    mach_hdr_t *IOKit_hdr = NULL;
    uintptr_t addr_IOServiceOpen = 0,
              addr_io_service_add_notification_ool = 0;
    struct nlist_64 *symtab = NULL;
    const char *strtab = NULL;
    uintptr_t cache_base = 0;

#ifdef TARGET_MACOS
    Dl_info IOKit_info;
    if(dladdr(IOServiceOpen, &IOKit_info) == 0)
    {
        DEBUG("Failed to find IOKit header.");
        goto out;
    }
    IOKit_hdr = IOKit_info.dli_fbase;
    if(syscall(294, &cache_base) != 0) // shared_region_check_np
    {
        DEBUG("Failed to find dyld_shared_cache: %s", strerror(errno));
        goto out;
    }
    DEBUG("dyld_shared_cache is at " ADDR, cache_base);
    dysc_hdr_t *cache_hdr = (dysc_hdr_t*)cache_base;
    dysc_seg_t *cache_segs = (dysc_seg_t*)(cache_base + cache_hdr->segoff);
    dysc_seg_t *cache_base_seg = NULL;
    for(size_t i = 0; i < cache_hdr->nsegs; ++i)
    {
        if(cache_segs[i].fileoff == 0 && cache_segs[i].size > 0)
        {
            cache_base_seg = &cache_segs[i];
            break;
        }
    }
    if(cache_base_seg == NULL)
    {
        DEBUG("No segment maps to cache base");
        goto out;
    }
#else
    // TODO: This will have to be reworked once there are more 64-bit sub-archs than just arm64.
    //       It's probably gonna be easiest to use PROC_PIDREGIONPATHINFO, at least that gives the full path on iOS.
    fd = open("/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64", O_RDONLY);
    if(fd == -1)
    {
        DEBUG("Failed to open dyld_shared_cache_arm64 for reading: %s", strerror(errno));
        goto out;
    }
    if(fstat(fd, &s) != 0)
    {
        DEBUG("Failed to stat(dyld_shared_cache_arm64): %s", strerror(errno));
        goto out;
    }
    cache = mmap(NULL, s.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if(cache == MAP_FAILED)
    {
        DEBUG("Failed to map dyld_shared_cache_arm64 to memory: %s", strerror(errno));
        goto out;
    }
    cache_base = (uintptr_t)cache;
    DEBUG("dyld_shared_cache is at " ADDR, cache_base);

    dysc_hdr_t *cache_hdr = cache;
    if(cache_hdr->nlocals == 0)
    {
        DEBUG("Cache contains no local symbols.");
        goto out;
    }
    dysc_local_info_t *local_info = (dysc_local_info_t*)(cache_base + cache_hdr->localoff);
    dysc_local_entry_t *local_entries = (dysc_local_entry_t*)((uintptr_t)local_info + local_info->entriesOffset);
    DEBUG("cache_hdr: " ADDR ", local_info: " ADDR ", local_entries: " ADDR, (uintptr_t)cache_hdr, (uintptr_t)local_info, (uintptr_t)local_entries);
    dysc_local_entry_t *local_entry = NULL;
    struct nlist_64 *local_symtab = (struct nlist_64*)((uintptr_t)local_info + local_info->nlistOffset);
    const char *local_strtab = (const char*)((uintptr_t)local_info + local_info->stringsOffset);
    for(size_t i = 0; i < local_info->entriesCount; ++i)
    {
        mach_hdr_t *dylib_hdr = (mach_hdr_t*)(cache_base + local_entries[i].dylibOffset);
        CMD_ITERATE(dylib_hdr, cmd)
        {
            if(cmd->cmd == LC_ID_DYLIB && strcmp((char*)cmd + ((struct dylib_command*)cmd)->dylib.name.offset, IOKIT_PATH) == 0)
            {
                IOKit_hdr = dylib_hdr;
                local_entry = &local_entries[i];
                local_symtab = &local_symtab[local_entries[i].nlistStartIndex];
                goto found;
            }
        }
    }
    DEBUG("Failed to find local symbols for IOKit.");
    goto out;

    found:;
    DEBUG("IOKit header: " ADDR ", local_symtab: " ADDR ", local_strtab: " ADDR, (uintptr_t)IOKit_hdr, (uintptr_t)local_symtab, (uintptr_t)local_strtab);
    for(size_t i = 0; i < local_entry->nlistCount; ++i)
    {
        const char *name = &local_strtab[local_symtab[i].n_un.n_strx];
        if(strcmp(name, "_io_service_add_notification_ool") == 0)
        {
            addr_io_service_add_notification_ool = local_symtab[i].n_value;
            break;
        }
    }
#endif
    struct symtab_command *symcmd = NULL;
    CMD_ITERATE(IOKit_hdr, cmd)
    {
        if(cmd->cmd == LC_SYMTAB)
        {
            symcmd = (struct symtab_command*)cmd;
#ifdef TARGET_MACOS
            for(size_t i = 0; i < cache_hdr->nsegs; ++i)
            {
                if(cache_segs[i].fileoff <= symcmd->symoff && cache_segs[i].fileoff + cache_segs[i].size > symcmd->symoff)
                {
                    symtab = (struct nlist_64*)(cache_base - cache_base_seg->addr + cache_segs[i].addr + symcmd->symoff - cache_segs[i].fileoff);
                }
                if(cache_segs[i].fileoff <= symcmd->stroff && cache_segs[i].fileoff + cache_segs[i].size > symcmd->stroff)
                {
                    strtab = (const char*)(cache_base - cache_base_seg->addr + cache_segs[i].addr + symcmd->stroff - cache_segs[i].fileoff);
                }
            }
#else
            symtab = (struct nlist_64*)(cache_base + symcmd->symoff);
            strtab = (const char*)(cache_base + symcmd->stroff);
#endif
            break;
        }
    }
    DEBUG("symcmd: " ADDR ", symtab: " ADDR ", strtab: " ADDR, (uintptr_t)symcmd, (uintptr_t)symtab, (uintptr_t)strtab);
    if(symcmd == NULL || symtab == NULL || strtab == NULL)
    {
        DEBUG("Failed to find IOKit symtab.");
        goto out;
    }
    for(size_t i = 0; i < symcmd->nsyms; ++i)
    {
        const char *name = &strtab[symtab[i].n_un.n_strx];
        if(strcmp(name, "_IOServiceOpen") == 0)
        {
            addr_IOServiceOpen = symtab[i].n_value;
        }
#ifdef TARGET_MACOS
        else if(strcmp(name, "_io_service_add_notification_ool") == 0)
        {
            addr_io_service_add_notification_ool = symtab[i].n_value;
        }
#endif
    }
    DEBUG("IOServiceOpen: " ADDR, addr_IOServiceOpen);
    DEBUG("io_service_add_notification_ool: " ADDR, addr_io_service_add_notification_ool);
    if(addr_IOServiceOpen == 0 || addr_io_service_add_notification_ool == 0)
    {
        goto out;
    }
    io_service_add_notification_ool = (void*)(IOServiceOpen - addr_IOServiceOpen + addr_io_service_add_notification_ool);
#else
    // 32-bit just exports the function
    io_service_add_notification_ool = dlsym(IOKit, "io_service_add_notification_ool");
    if(io_service_add_notification_ool == NULL)
    {
        DEBUG("Failed to find io_service_add_notification_ool.");
        goto out;
    }
#endif

    uint32_t dict[] =
    {
        kOSSerializeMagic,
        kOSSerializeEndCollection | kOSSerializeDictionary | (size / (2 * sizeof(void*))),
        kOSSerializeSymbol | 4,
        0x636261, // "abc"
        kOSSerializeEndCollection | kOSSerializeBoolean | 1,
    };
    kern_return_t err;
    ret = io_service_add_notification_ool(master, "IOServiceTerminate", dict, sizeof(dict), MACH_PORT_NULL, NULL, 0, &err, &port);
    if(ret == KERN_SUCCESS)
    {
        ret = err;
    }
    if(ret != KERN_SUCCESS)
    {
        DEBUG("Failed to create IONotification: %s", mach_error_string(ret));
        port = MACH_PORT_NULL; // Just in case
        goto out;
    }

    out:;
    if(IOKit != NULL)
    {
        dlclose(IOKit);
    }
#if defined(__LP64__) && !defined(TARGET_MACOS)
    if(cache != NULL)
    {
        munmap(cache, s.st_size);
    }
    if(fd != 0 )
    {
        close(fd);
    }
#endif
    return port;
}

typedef struct
{
    uint32_t num_of_size[16];
    vm_size_t page_size;
    vm_size_t alloc_size;
    vm_address_t vtab;
} get_kernel_base_ios9_cb_args_t;

// Memory tag
#define VM_KERN_MEMORY_LIBKERN 4

// Amount of pages that are too large for zalloc
#define KALLOC_DIRECT_THRESHOLD 3

static bool count_libkern_allocations(vm_address_t addr, vm_size_t size, vm_region_submap_info_data_64_t *info, void *arg)
{
    get_kernel_base_ios9_cb_args_t *args = arg;
    if(info->user_tag == VM_KERN_MEMORY_LIBKERN)
    {
        DEBUG("Found libkern region " ADDR "-" ADDR "...", addr, addr + size);
        size_t idx = (size + args->page_size - 1) / args->page_size;
        if(idx < KALLOC_DIRECT_THRESHOLD)
        {
            DEBUG("Too small, skipping...");
        }
        else
        {
            idx -= KALLOC_DIRECT_THRESHOLD;
            if(idx >= sizeof(args->num_of_size)/sizeof(args->num_of_size[0]))
            {
                DEBUG("Too large, skipping...");
            }
            else
            {
                ++(args->num_of_size[idx]);
            }
        }
    }
    return true;
}

static bool get_kernel_base_ios9_cb(vm_address_t addr, vm_size_t size, vm_region_submap_info_data_64_t *info, void *arg)
{
    get_kernel_base_ios9_cb_args_t *args = arg;
    if(info->user_tag == VM_KERN_MEMORY_LIBKERN && size == args->alloc_size)
    {
        DEBUG("Found matching libkern region " ADDR "-" ADDR ", dumping it...", addr, addr + size);
        vm_address_t obj = 0;
        if(kernel_read(addr, sizeof(void*), &obj) != sizeof(void*))
        {
            DEBUG("Kernel I/O error, aborting.");
            return false;
        }
        DEBUG("Found object: " ADDR, obj);
        if(obj < KERNEL_SPACE)
        {
            return false;
        }
        vm_address_t vtab = 0;
        if(kernel_read(obj, sizeof(void*), &vtab) != sizeof(void*))
        {
            DEBUG("Kernel I/O error, aborting.");
            return false;
        }
        DEBUG("Found vtab: " ADDR, vtab);
        if(vtab < KERNEL_SPACE)
        {
            return false;
        }
        args->vtab = vtab;
        return false; // just to short-circuit, we ignore the return value in the calling func
    }
    return true;
}

static vm_address_t get_kernel_base_ios9(vm_address_t regstart, vm_address_t regend)
{
    get_kernel_base_ios9_cb_args_t args =
    {
        .num_of_size = {0},
        .page_size = 0,
        .alloc_size = 0,
        .vtab = 0,
    };

    host_t host = mach_host_self();
    kern_return_t ret = host_page_size(host, &args.page_size);
    if(ret != KERN_SUCCESS)
    {
        DEBUG("Failed to get host page size: %s", mach_error_string(ret));
        return 0;
    }

    DEBUG("Enumerating libkern allocations...");
    if(!foreach_kernel_region(&count_libkern_allocations, &args))
    {
        return 0;
    }
    for(size_t i = 0; i < sizeof(args.num_of_size)/sizeof(args.num_of_size[0]); ++i)
    {
        if(args.num_of_size[i] == 0)
        {
            args.alloc_size = (i + KALLOC_DIRECT_THRESHOLD) * args.page_size;
            break;
        }
    }
    if(args.alloc_size == 0)
    {
        DEBUG("Failed to find a suitable size for injection, returning 0.");
        return 0;
    }

    DEBUG("Making allocation of size " SIZE "...", args.alloc_size);
    mach_port_t port = libkern_allocate(args.alloc_size);
    if(port == MACH_PORT_NULL)
    {
        return 0;
    }
    foreach_kernel_region(&get_kernel_base_ios9_cb, &args); // don't care about return value
    mach_port_deallocate(mach_task_self(), port);

    if(args.vtab == 0)
    {
        DEBUG("Failed to get any vtab, returning 0.");
        return 0;
    }

    DEBUG("Starting at " ADDR ", searching backwards...", args.vtab);
    for(vm_address_t addr = (args.vtab & ~0xfffff) +
#if TARGET_OSX
            0                   // no offset for macOS
#else
#   ifdef __LP64__
            2 * IMAGE_OFFSET    // 0x4000 for 64-bit on >=9.0
#   else
            IMAGE_OFFSET        // 0x1000 for 32-bit, regardless of OS version
#   endif
#endif
        ; addr > regstart; addr -= 0x100000)
    {
        mach_hdr_t hdr;
        DEBUG("Looking for mach header at " ADDR "...", addr);
        if(kernel_read(addr, sizeof(hdr), &hdr) != sizeof(hdr))
        {
            DEBUG("Kernel I/O error, returning 0.");
            return 0;
        }
        if(hdr.magic == MACH_HEADER_MAGIC && hdr.filetype == MH_EXECUTE)
        {
            DEBUG("Found Mach-O of type MH_EXECUTE at " ADDR ", returning success.", addr);
            return addr;
        }
    }

    DEBUG("Found no mach header, returning 0.");
    return 0;
}

static vm_address_t get_kernel_base_ios8(vm_address_t regstart)
{
    // things used to be so simple...
    vm_address_t addr = regstart + IMAGE_OFFSET + 0x200000;

    mach_hdr_t hdr;
    DEBUG("Looking for mach header at " ADDR "...", addr);
    if(kernel_read(addr, sizeof(hdr), &hdr) != sizeof(hdr))
    {
        DEBUG("Kernel I/O error, returning 0.");
        return 0;
    }
    if(hdr.magic == MACH_HEADER_MAGIC && hdr.filetype == MH_EXECUTE)
    {
        DEBUG("Success!");
    }
    else
    {
        DEBUG("Not a Mach-O header there, subtracting 0x200000.");
        addr -= 0x200000;
    }
    return addr;
}

typedef struct
{
    vm_address_t regstart;
    vm_address_t regend;
} get_kernel_base_cb_args_t;

static bool get_kernel_base_cb(vm_address_t addr, vm_size_t size, vm_region_submap_info_data_64_t *info, void *arg)
{
    get_kernel_base_cb_args_t *args = arg;
    DEBUG("Found region " ADDR "-" ADDR " with %c%c%c", addr, addr + size, (info->protection) & VM_PROT_READ ? 'r' : '-', (info->protection) & VM_PROT_WRITE ? 'w' : '-', (info->protection) & VM_PROT_EXECUTE ? 'x' : '-');
    if
    (
        (info->protection & (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE)) == 0 &&
#ifdef TARGET_MACOS
        addr ==     0xffffff8000000000 &&
#else
        size >          1024*1024*1024 &&
#   ifdef __LP64__
        size <= 16ULL * 1024*1024*1024 && // this is always true for 32-bit
#   endif
#endif
        info->share_mode == SM_EMPTY
    )
    {
        if(args->regstart == 0 && args->regend == 0)
        {
            DEBUG("Found a matching memory region.");
            args->regstart = addr;
            args->regend   = addr + size;
        }
        else
        {
            DEBUG("Found more than one matching memory region, aborting.");
            return false;
        }
    }

    return true;
}

vm_address_t get_kernel_base(void)
{
    static vm_address_t kbase = 0;
    static bool initialized = false;
    if(!initialized)
    {
        DEBUG("Getting kernel base address...");

        DEBUG("Getting base region address...");
        get_kernel_base_cb_args_t args =
        {
            .regstart = 0,
            .regend = 0,
        };
        if(!foreach_kernel_region(&get_kernel_base_cb, &args))
        {
            return 0;
        }
        if(args.regstart == 0)
        {
            DEBUG("Failed to find base region, returning 0.");
            return 0;
        }
        if(args.regend < args.regstart)
        {
            DEBUG("Base region has overflowing size, returning 0.");
            return 0;
        }
        DEBUG("Base region is at " ADDR "-" ADDR ".", args.regstart, args.regend);

        vm_address_t addr = HAVE_TAGGED_REGIONS ? get_kernel_base_ios8(args.regstart) : get_kernel_base_ios9(args.regstart, args.regend);
        if(addr == 0)
        {
            return 0;
        }

        DEBUG("Got address " ADDR ", doing sanity checks...", addr);
        mach_hdr_t hdr;
        if(kernel_read(addr, sizeof(hdr), &hdr) != sizeof(hdr))
        {
            DEBUG("Kernel I/O error, returning 0.");
            return 0;
        }
        if(hdr.magic != MACH_HEADER_MAGIC)
        {
            DEBUG("Header has wrong magic, returning 0 (%08x)", hdr.magic);
            return 0;
        } else {
            printf("Found magic %08x at %p\n", hdr.magic, addr);
        }
        if(hdr.filetype != MH_EXECUTE)
        {
            DEBUG("Header has wrong filetype, returning 0 (%u)", hdr.filetype);
            return 0;
        }
        if(hdr.cputype != MACH_TYPE)
        {
            DEBUG("Header has wrong architecture, returning 0 (%u)", hdr.cputype);
            return 0;
        }
        void *cmds = malloc(hdr.sizeofcmds);
        if(cmds == NULL)
        {
            DEBUG("Memory allocation error, returning 0.");
            return 0;
        }
        if(kernel_read(addr + sizeof(hdr), hdr.sizeofcmds, cmds) != hdr.sizeofcmds)
        {
            DEBUG("Kernel I/O error, returning 0.");
            free(cmds);
            return 0;
        }
        bool has_userland_address = false,
             has_linking = false,
             has_unixthread = false,
             has_exec = false;
        for
        (
            struct load_command *cmd = cmds, *end = (struct load_command*)((char*)cmds + hdr.sizeofcmds);
            cmd < end;
            cmd = (struct load_command*)((char*)cmd + cmd->cmdsize)
        )
        {
            switch(cmd->cmd)
            {
                case MACH_LC_SEGMENT:
                    {
                        mach_seg_t *seg = (mach_seg_t*)cmd;
                        if(seg->vmaddr < KERNEL_SPACE)
                        {
                            has_userland_address = true;
                            goto end;
                        }
                        if(seg->initprot & VM_PROT_EXECUTE)
                        {
                            has_exec = true;
                        }
                        break;
                    }
                case LC_UNIXTHREAD:
                    has_unixthread = true;
                    break;
                case LC_LOAD_DYLIB:
                case LC_ID_DYLIB:
                case LC_LOAD_DYLINKER:
                case LC_ID_DYLINKER:
                case LC_PREBOUND_DYLIB:
                case LC_LOAD_WEAK_DYLIB:
                case LC_REEXPORT_DYLIB:
                case LC_LAZY_LOAD_DYLIB:
                case LC_DYLD_INFO:
                case LC_DYLD_INFO_ONLY:
                case LC_DYLD_ENVIRONMENT:
                case LC_MAIN:
                    has_linking = true;
                    goto end;
            }
        }
        end:;
        free(cmds);
        if(has_userland_address)
        {
            DEBUG("Found segment with userland address, returning 0.");
            return 0;
        }
        if(has_linking)
        {
            DEBUG("Found linking-related load command, returning 0.");
            return 0;
        }
        if(!has_unixthread)
        {
            DEBUG("Binary is missing LC_UNIXTHREAD, returning 0.");
            return 0;
        }
        if(!has_exec)
        {
            DEBUG("Binary has no executable segment, returning 0.");
            return 0;
        }

        DEBUG("Confirmed base address " ADDR ", caching it.", addr);
        kbase = addr;
        initialized = true;
    }
    return kbase;
}

vm_size_t kernel_read(vm_address_t addr, vm_size_t size, void *buf)
{
    DEBUG("Reading kernel bytes " ADDR "-" ADDR, addr, addr + size);
    kern_return_t ret;
    task_t kernel_task;
    vm_size_t remainder = size,
              bytes_read = 0;

    ret = get_kernel_task(&kernel_task);
    if(ret != KERN_SUCCESS)
    {
        return -1;
    }

    // The vm_* APIs are part of the mach_vm subsystem, which is a MIG thing
    // and therefore has a hard limit of 0x1000 bytes that it accepts. Due to
    // this, we have to do both reading and writing in chunks smaller than that.
    for(vm_address_t end = addr + size; addr < end; remainder -= size)
    {
        size = remainder > MAX_CHUNK_SIZE ? MAX_CHUNK_SIZE : remainder;
        ret = vm_read_overwrite(kernel_task, addr, size, (vm_address_t)&((char*)buf)[bytes_read], &size);
        if(ret != KERN_SUCCESS || size == 0)
        {
            DEBUG("vm_read error: %s", mach_error_string(ret));
            break;
        }
        bytes_read += size;
        addr += size;
    }

    return bytes_read;
}

vm_size_t kernel_write(vm_address_t addr, vm_size_t size, void *buf)
{
    printf("Writing to kernel at %x\n", addr);
    sleep(1);
    kern_return_t ret;
    task_t kernel_task;
    vm_size_t remainder = size,
              bytes_written = 0;

    ret = get_kernel_task(&kernel_task);
    if(ret != KERN_SUCCESS)
    {
        return -1;
    }
    printf("Got kernel task\n");
    sleep(1);
    for(vm_address_t end = addr + size; addr < end; remainder -= size)
    {
        printf("Writing %d bytes at addr %x", size, addr);
        sleep(1);
        size = remainder > MAX_CHUNK_SIZE ? MAX_CHUNK_SIZE : remainder;
        ret = vm_write(kernel_task, addr, (vm_offset_t)&((char*)buf)[bytes_written], size);
        if(ret != KERN_SUCCESS)
        {
            printf("vm_write error: %s", mach_error_string(ret));
            break;
        }
        bytes_written += size;
        addr += size;
    }

    return bytes_written;
}

vm_address_t kernel_find(vm_address_t addr, vm_size_t len, void *buf, size_t size)
{
    vm_address_t ret = 0;
    unsigned char* b = malloc(len);
    if(b)
    {
        // TODO reading in chunks would probably be better
        if(kernel_read(addr, len, b))
        {
            void *ptr = memmem(b, len, buf, size);
            if(ptr)
            {
                ret = addr + ((char*)ptr - (char*)b);
            }
        }
        free(b);
    }
    return ret;
}
