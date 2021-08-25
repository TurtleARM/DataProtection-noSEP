#include <stdio.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <hfs/hfsplus.h>
#include <openssl/aes.h>
#include "hfs/hfslib.h"
#include "emf.h"

size_t ConvertHexaCFString(CFStringRef s, uint8_t** bytes)
{
	uint32_t len = CFStringGetLength(s);
	uint8_t* hex = malloc(len+1);
	
	if(hex == NULL)
		return 0;
	
	if(!CFStringGetCString(s, hex, len+1, kCFStringEncodingASCII))
	{
		free(hex);
		return 0;
	}
	size_t size = 0;
	hexToBytes(hex, bytes, &size);
	free(hex);
	return size;
}

void grabClassKey(const void *key, const void *value, void *context)
{
	EMFInfo* emf = (EMFInfo*) context;
	uint8_t* class_key = NULL;
	
	if(CFGetTypeID(key) != CFStringGetTypeID() || CFGetTypeID(value) != CFStringGetTypeID())
		return;
	
	SInt32 clas = CFStringGetIntValue((CFStringRef)key);

	if(clas > 0 && clas <= MAX_CLASS_KEYS && CFStringGetLength((CFStringRef) value) == 64)
	{
		if(ConvertHexaCFString(value, &class_key) == 32)
		{
			AES_set_decrypt_key(class_key, 32*8, &(emf->classKeys[clas-1]));
			free(class_key);
			emf->classKeys_bitset |= 1 << clas;
		}
	}
	
}

void readHex(uint8_t *buf, int len, char *fn) {
    FILE *fptr = fopen(fn, "r");
    int i;
    if (fptr == NULL) {
        printf("Error opening fd\n");
        return;
    }
    for (i = 0; i < len; i++) {
        if (fscanf(fptr, "%X", &buf[i]) < 1) {
            printf("Error reading from fd\n");
            return;
        }
    }
    fclose(fptr);
}

int readInt(char *fn) {
	FILE *fptr = fopen(fn, "r");
	int number;
	if (fptr == NULL) {
        printf("Error opening fd\n");
        return -1;
    }
	if (fscanf(fptr, "%d", &number) < 1) {
		printf("Error reading from fd\n");
		return -1;
    }
	return number;
}

LwVMInfo *LwVM_init(Volume *volume, char *imagePath) {
	uint8_t *lwvmk = malloc(32);
	uint8_t *dkey = malloc(32);
	uint32_t dataVolumeOffset = readInt("volumeoffset.txt");
	if (dataVolumeOffset < 0) {
		exit(0);
	}
	readHex(lwvmk, 32, "lwvmk.txt");
	readHex(dkey, 32, "dkey.txt");
	printf("LwVM Key: ");
	printHex(lwvmk, 32);
	printf("DKey: ");
	printHex(dkey, 32);
	uint64_t volume_id = *((uint64_t*) (&volume->volumeHeader->finderInfo[6]));
	FLIPENDIAN(volume_id);
	
	if(imagePath == NULL)
		imagePath = ".";
		
	printf("Volume identifier : %llx\n", volume_id);
	LwVMInfo *lwvmInfo = malloc(sizeof(LwVMInfo));
	if(lwvmInfo == NULL)
		return NULL;

	memset(lwvmInfo, 0, sizeof(LwVMInfo));
	lwvmInfo->volume = volume;
	lwvmInfo->volume_offset = dataVolumeOffset;
	printf("Volume offset: %d\n", dataVolumeOffset);

	AES_set_encrypt_key(lwvmk, 32*8, &(lwvmInfo->lwvmkey));
	AES_set_decrypt_key(dkey, 32*8, &(lwvmInfo->classKeys[CLASS_DKEY-1]));
	lwvmInfo->classKeys_bitset |= 1 << CLASS_DKEY;
	free(lwvmk);
	free(dkey);
	return lwvmInfo;
}

EMFInfo* EMF_init(Volume* volume, char* imagePath)
{
	uint8_t* emfk = NULL;
	uint8_t* dkey = NULL;
	
	uint64_t volume_id = *((uint64_t*) (&volume->volumeHeader->finderInfo[6]));
	FLIPENDIAN(volume_id);
	
	if(imagePath == NULL)
		imagePath = ".";
		
	printf("Volume identifier : %llx\n", volume_id);
	printf("Searching for %s/%llx.plist\n", imagePath, volume_id);
	
	CFStringRef path = CFStringCreateWithFormat(NULL, NULL, CFSTR("%s/%llx.plist"), imagePath, volume_id);
	
	CFURLRef fileURL = CFURLCreateWithFileSystemPath(NULL, path, kCFURLPOSIXPathStyle, FALSE);
	CFRelease(path);
	
	CFReadStreamRef stream = CFReadStreamCreateWithFile(NULL, fileURL);
	CFRelease(fileURL);
	
	if(stream == NULL)
	{
		return NULL;
	}
	if(!CFReadStreamOpen(stream))
	{
		fprintf(stderr, "Cannot open file\n");
		return NULL;
	}
	CFPropertyListRef dict = CFPropertyListCreateWithStream(NULL, stream, 0, kCFPropertyListImmutable, NULL, NULL);

	CFRelease(stream);
	
	if (dict == NULL || CFGetTypeID(dict) != CFDictionaryGetTypeID())
		return NULL;
	
	CFStringRef emfHex = CFDictionaryGetValue(dict, CFSTR("EMF"));
	CFStringRef dkeyHex = CFDictionaryGetValue(dict, CFSTR("DKey"));
	CFNumberRef dataVolumeOffset = CFDictionaryGetValue (dict, CFSTR("dataVolumeOffset"));
	
	if (emfHex == NULL || CFGetTypeID(emfHex) != CFStringGetTypeID())
		return NULL;
	if (dkeyHex == NULL || CFGetTypeID(dkeyHex) != CFStringGetTypeID())
		return NULL;
	if (dataVolumeOffset == NULL || CFGetTypeID(dataVolumeOffset) != CFNumberGetTypeID())
		return NULL;

	EMFInfo* emf = malloc(sizeof(EMFInfo));
	
	if(emf == NULL)
		return NULL;

	memset(emf, 0, sizeof(EMFInfo));
	
	emf->volume = volume;
	
	CFNumberGetValue(dataVolumeOffset, kCFNumberLongType, &emf->volume_offset);
	
	printf("Data partition offset = %llx\n", emf->volume_offset);
	
	if(ConvertHexaCFString(emfHex, &emfk) != 32)
	{
		fprintf(stderr, "Invalid EMF key\n");
		free(emf);
		return NULL;
	}
	if(ConvertHexaCFString(dkeyHex, &dkey) != 32)
	{
		fprintf(stderr, "Invalid DKey key\n");
		free(emf);
		return NULL;
	}
	
	AES_set_encrypt_key(emfk, 32*8, &(emf->emfkey));
	AES_set_decrypt_key(dkey, 32*8, &(emf->classKeys[CLASS_DKEY-1]));
	emf->classKeys_bitset |= 1 << CLASS_DKEY;
	
	CFDictionaryRef classKeys = CFDictionaryGetValue(dict, CFSTR("classKeys"));
	
	if(classKeys != NULL && CFGetTypeID(classKeys) == CFDictionaryGetTypeID())
	{
		printf("Reading class keys, NSProtectionComplete files should be decrypted OK\n");
		CFDictionaryApplyFunction(classKeys, grabClassKey, (void*) emf);
	}
	else
	{
		printf("Only NSProtectionNone files will be decrypted\n");
	}
	
	free(emfk);
	free(dkey);
	return emf;
}
