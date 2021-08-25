#include <stdio.h>
#include <IOKit/IOKitLib.h>
#include <string.h>
#include "AppleEffaceableStorage.h"
#include "IOKit.h"
#include <CoreFoundation/CoreFoundation.h>
#include "dp/ramdisk_tools/bsdcrypto/key_wrap.h"
#include "dp/ramdisk_tools/IOAESAccelerator.h"
#include "LockerManager.h"
#include "dp/ramdisk_tools/AppleKeyStore.h"
#include "dp/ramdisk_tools/device_info.h"
#include "dp/ramdisk_tools/util.h"

#define WRAPPEDKEYSIZE 40

uint8_t lockers[960] = {0};

struct LwVMPartitionKey {
    uint8_t uuid[16];
    uint8_t key[32];
};

struct LwVMKeyBag {
    uint8_t random[12];
    uint32_t num_keys;
    uint8_t media_uuid[16];
    //struct LwVMPartitionKey keys[1];
    uint8_t uuid[16];
    uint8_t key[32];
};

void printHex(uint8_t *buf, int len) {
    int i;
    for (i = 0; i < len; i++)
    {
        printf("\\x");
        printf("%02X", buf[i]);
    }
    printf("\n");
}

void writeHex(uint8_t *buf, int len, char *fn) {
    int i;
    FILE *fptr = fopen(fn, "w");
    if (fptr == NULL) {
        printf("Error opening fd\n");
        return;
    }
    for (i = 0; i < len; i++)
    {
        if (i > 0) fprintf(fptr, " ");
        fprintf(fptr, "%02X", buf[i]);
    }
    fclose(fptr);
}

void writeInt(uint32_t number, char *fn) {
    FILE *fptr = fopen(fn, "w");
    if (fptr == NULL) {
        printf("Error opening fd\n");
        return;
    }
    fprintf(fptr, "%d", number);
    fclose(fptr);
}

void getKeyMaterial() {
    uint8_t dkey[WRAPPEDKEYSIZE] = {0};
    uint8_t lwvm[80] = {0};
    uint8_t emf[36] = {0};

    struct HFSInfos hfsinfos={0};
    struct BAG1Locker bag1 = { 0 };

    getHFSInfos(&hfsinfos);

    uint8_t* key835 = IOAES_key835();
    uint8_t* key89A = IOAES_key89A();
    uint8_t* key89B = IOAES_key89B();

    if (AppleEffaceableStorage__getBytes(lockers, 960)) {
        fprintf(stderr, "Error getting locker bytes\n");
        return;
    }
    CFMutableDictionaryRef out = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                                            0,
                                                            &kCFTypeDictionaryKeyCallBacks,
                                                            &kCFTypeDictionaryValueCallBacks);
    if (AppleEffaceableStorage__getLockerFromBytes(LOCKER_DKEY, lockers, 960, dkey, WRAPPEDKEYSIZE)) {
        fprintf(stderr, "Error getting DKEY locker content\n");
        return;
    }
    if (AppleEffaceableStorage__getLockerFromBytes(LOCKER_BAG1, lockers, 960, (uint8_t*)&bag1, sizeof(struct BAG1Locker))) {
        fprintf(stderr, "Error getting BAG1 locker content\n");
        return;
    }
    if (AppleEffaceableStorage__getLockerFromBytes(LOCKER_EMF, lockers, 960, emf, 36)) {
        fprintf(stderr, "Error getting EMF locker content, trying LwVM\n");
        if (AppleEffaceableStorage__getLockerFromBytes(LOCKER_LWVM, lockers, 960, lwvm, 0x50)) {
            fprintf(stderr, "Error getting LwVM locker content\n");
            return;
        }
    }

    printf("Wrapped DKey: ");
    printHex(dkey, WRAPPEDKEYSIZE);
    // Unwrapping
    aes_key_wrap_ctx ctx;
    aes_key_wrap_set_key(&ctx, key835, 16);
    if(aes_key_unwrap(&ctx, dkey, dkey, 32/8)) {
        printf("FAIL unwrapping DKey with key 0x835\n");
        return;
    }
    printf("Key 0x835: ");
    printHex(key835, 16);
    printf("DKey: ");
    printHex(dkey, 32);
    writeHex(dkey, 32, "dkey.txt");
    printf("BAG1 Key: ");
    printHex(bag1.key, 32);
    writeHex(bag1.key, 32, "bag1k.txt");
    printf("BAG1 IV: ");
    printHex(bag1.iv, 16);
    writeHex(bag1.iv, 16, "bag1iv.txt");
    doAES(lwvm, lwvm, 0x50, kIOAESAcceleratorCustomMask, key89B, NULL, kIOAESAcceleratorDecrypt, 128);
    memcpy(&emf[4], &lwvm[32+16], 32);
    printf("EMF Key: ");
    printHex(&emf[4], 32);
    writeHex(&emf[4], 32, "lwvmk.txt");
    writeInt(hfsinfos.dataVolumeOffset, "volumeoffset.txt");
    printf("Block size: %d\n", hfsinfos.blockSize);
}

void getPasscodeKey(const char *passcode, int iternum) {
    u_int8_t passcodeKey[32]={0};
    if (AppleKeyStore_getPasscodeKey10(passcode, 4, passcodeKey, iternum)) {
        printf("Error deriving passcode key\n");
        return;
    }
    printf("Passcode Key: ");
    printHex(passcodeKey, 32);
}

int main() {
    int option;
    int iternum;
    char passcode[4];
    printf("Locker Manager options:\n");
    printf("1: Get Cryptographic Material\n");
    printf("2: Derive passcode key\n");
    printf("Option: ");
    scanf("%d", &option);
    switch (option) {
        case 1:
            getKeyMaterial();
            break;
        case 2: {
            printf("Insert passcode: ");
            scanf("%s", passcode);
            printf("Insert number of iterations: ");
            scanf("%d", &iternum);
            printf("Deriving passcode key...\n");
            getPasscodeKey(passcode, iternum);
            break;
        }
        default:
            printf("Unknown option, quitting...\n");
    }
	return 0;
}
