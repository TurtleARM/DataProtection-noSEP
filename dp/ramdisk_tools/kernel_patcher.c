#include <stdio.h>
#include <unistd.h>
#include <CoreFoundation/CoreFoundation.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include "../LockerManager.h"
#include "../../kernel_tools/libkern.h";
#include "../ramdisk_tools/ttbthingy.h"

mach_port_t kernel_task=0;

kern_return_t write_kernel(mach_port_t p, void* addr, uint32_t value)
{
    pointer_t buf;
    unsigned int sz;
    
    kern_return_t r = vm_write(p, (vm_address_t)addr, (vm_address_t)&value, sizeof(value));
    if (r)
    {
        fprintf(stderr, "vm_write into kernel_task failed\n");
    }
    else
    {
        //fix cache issue
        vm_read(p, (vm_address_t) addr, sizeof(value), &buf, &sz);
        fprintf(stderr, "vm_write into kernel_task OK %x\n", *((uint32_t*) buf));
    }
    return r;
}

// Only works up to iOS 7
vm_address_t get_kernel_base_ios7()
{
    kern_return_t ret;
    task_t kernel_task;
    vm_region_submap_info_data_64_t info;
    vm_size_t size;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    unsigned int depth = 0;
    vm_address_t addr = 0x81200000;
    //arm64
    //addr = 0xffffff8000000000;

    ret = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &kernel_task);
    if (ret != KERN_SUCCESS) {
        printf("task_for_pid(0) returned=%x\n", ret);
        return -1;
    }
    printf("Looking for kernel base address...\n");
    while (1) {
        // recurse to next vm region at depth=1, if it's big enough it's probably the kernel image
        ret = vm_region_recurse_64(kernel_task, &addr, &size, &depth, (vm_region_info_t) & info, &info_count);
        printf("addr=0x%llx\n", addr);
        if (ret != KERN_SUCCESS)
            break;
        if (size > 1024 * 1024 * 1024)
            return addr;
        addr += size;
    }

    return -1;
}

int patch_IOAESAccelerator()
{
    uint32_t i;
    pointer_t buf;
    unsigned int sz;
    bool second = false;
    mach_port_t kernel_task = MACH_PORT_NULL;
    host_t host = mach_host_self();
    kern_return_t ret = host_get_special_port(host, HOST_LOCAL_NODE, 4, &kernel_task);
    vm_address_t base = get_kernel_base();
    vm_address_t slide = base - 0x80001000;
    vm_address_t IOAESAccelerator10 = 0x808f4bd8;
    printf("kernel_base=%p\n", (void*) base);
    printf("kernel slide=%x\n", slide);
    //"IOAESAccelerator enable UID" : (h("67 D0 40 F6"), h("00 20 40 F6")) for iOS 5
    // B2 F5 FA 6F 00 F0 96 80  -> B2 F5 FA 6F 00 20 00 20 for iOS 10
    if (dothingy(slide)) {
        printf("Error patching kernel\n");
        exit(0);
    }
    return 0;
}
