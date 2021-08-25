#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <inttypes.h>
#include <libgen.h>
#include <inttypes.h>
#include <openssl/aes.h>
#include <hfs/hfslib.h>
#include "emf.h"

char endianness;

void TestByteOrder()
{
	short int word = 0x0001;
	char *byte = (char *) &word;
	endianness = byte[0] ? IS_LITTLE_ENDIAN : IS_BIG_ENDIAN;
}

void iv_for_lba(uint32_t lba, uint32_t* iv)
{
	int i;
	for(i = 0; i < 4; i++)
	{
		if(lba & 1)
			lba = 0x80000061 ^ (lba >> 1);
		else
			lba = lba >> 1;
		iv[i] = lba;
	}
}

int EMF_unwrap_filekey_forclass(LwVMInfo* emf, uint8_t* wrapped_file_key, uint32_t protection_class_id, AES_KEY* file_key)
{
	uint8_t fk[32]={0};

	if (protection_class_id < 1 || protection_class_id >= MAX_CLASS_KEYS)
		return -1;

	if ((emf->classKeys_bitset & (1 << protection_class_id)) == 0)
	{
		printf("Class key %d not available\n", protection_class_id);
		return -1;
	}
	// Unwrap per-file key with DKey
	if(AES_unwrap_key(&(emf->classKeys[protection_class_id-1]), NULL, fk, wrapped_file_key, 40)!= 32)
	{
		fprintf(stderr, "EMF_unwrap_filekey_forclass unwrap FAIL, protection_class_id=%d\n", protection_class_id);
		return -1;
	}
	printf("Per-file key: ");
	printHex(fk, 32); 
	AES_set_decrypt_key(fk, 32*8, file_key);

	return 0;
}

void EMF_fix_and_decrypt_block(LwVMInfo* emf, uint8_t* buffer, uint32_t lba, uint32_t blockSize, AES_KEY* filekey)
{
	uint32_t volumeOffset = emf->volume_offset;
	printf("volume_offset: %d\n", volumeOffset);
	uint32_t iv[4];
	
	//reencrypt with emf key to get correct ciphertext
	iv_for_lba(volumeOffset + lba, iv);
	AES_cbc_encrypt(buffer, buffer, blockSize, &(emf->lwvmkey), (uint8_t*) iv, AES_ENCRYPT);
	printf("Encrypt IV: ");
	printHex((uint8_t *) iv, 16);
	//decrypt with file key
	iv_for_lba(volumeOffset + lba, iv);
	printf("Decrypt IV: ");
	printHex((uint8_t *) iv, 16);
	AES_cbc_encrypt(buffer, buffer, blockSize, filekey, (uint8_t*) iv, AES_DECRYPT);
}

int EMF_decrypt_file_blocks(LwVMInfo* emf, HFSPlusCatalogFile* file, uint8_t* wrapped_file_key, uint32_t protection_class)
{
	AES_KEY filekey;
	
	if(EMF_unwrap_filekey_forclass(emf, wrapped_file_key, protection_class, &filekey))
	{
		fprintf(stderr, "Cannot unwrap filekey for class %d\n", protection_class);
		return -1;
	}
	
	io_func* io = openRawFile(file->fileID, &file->dataFork, (HFSPlusCatalogRecord*)file, emf->volume);
	if(io == NULL)
	{
		fprintf(stderr, "openRawFile %d FAIL!\n", file->fileID);
		return -1;
	}
	RawFile* rawFile = (RawFile*) io->data;

	Extent* extent = rawFile->extents;
	uint32_t blockSize = emf->volume->volumeHeader->blockSize;
   	uint32_t i;
	uint8_t* buffer = malloc(blockSize);
	
	if(buffer == NULL)
		return -1;

	//decrypt all blocks in all extents
	//the last block can contain stuff from erased files maybe ?
	printf("Decrypting file blocks...\n");
	while(extent != NULL)
	{
		for(i=0; i < extent->blockCount; i++)
		{
			if(READ(emf->volume->image, (extent->startBlock + i) * blockSize, blockSize, buffer))
			{
				printf("block content before\n");
				printHex(buffer, blockSize);
				EMF_fix_and_decrypt_block(emf, buffer, extent->startBlock + i, blockSize, &filekey);
				//write back to image
				printf("block content after\n");
				printHex(buffer, blockSize);
				WRITE(emf->volume->image, (extent->startBlock + i) * blockSize, blockSize, buffer);
			}
		}
		extent = extent->next;
	}
	free(buffer);
	return 0;
}

void printHex(uint8_t *buf, int len) {
    int i;
    for (i = 0; i < len; i++)
    {
        printf("\\x");
        printf("%02X", buf[i]);
    }
    printf("\n");
}

/*
typedef struct EMFInfo
{
	Volume* volume;
	uint64_t volume_id;
	uint64_t volume_offset;
	uint32_t classKeys_bitset;
	AES_KEY emfkey;
	AES_KEY classKeys[MAX_CLASS_KEYS];
}EMFInfo;
*/

int EMF_decrypt_folder(LwVMInfo* emf, HFSCatalogNodeID folderID)
{
	CatalogRecordList* list;
	CatalogRecordList* theList;
	HFSPlusCatalogFolder* folder;
	HFSPlusCatalogFile* file;
	char* name;
	cprotect_xattr_v5* cprotect_xattr;
	uint8_t* wrapped_file_key;
	// get root folderID content
	theList = list = getFolderContents(folderID, emf->volume);

	// Navigate B-Tree to retrieve folderID content
	while(list != NULL)
	{
		// name is just folders
		name = unicodeToAscii(&list->name);
		if(list->record->recordType == kHFSPlusFolderRecord)
		{
			// Decrypt subfolder recursively
			folder = (HFSPlusCatalogFolder*)list->record;
			EMF_decrypt_folder(emf, folder->folderID);
		}
		else if(list->record->recordType == kHFSPlusFileRecord)
		{
			if (strcmp(name, "Dfile.txt") != 0) {
				free(name);
				list = list->next;
				continue;
			} 
			printf("Decrypting %s\n", name);
			// Decrypt file record with EMF -> Get cprotect xattr -> Unwrap cprotect with class key
			file = (HFSPlusCatalogFile*)list->record;
			printf("Last access date: %u\n", file->accessDate);
			printf("Logical size: %"PRIu64"\n", file->dataFork.logicalSize);
			size_t attr_len = getAttribute(emf->volume, file->fileID, "com.apple.system.cprotect", (uint8_t**) &cprotect_xattr);
			
			if(cprotect_xattr != NULL && attr_len > 0)
			{
				if (cprotect_xattr->xattr_major_version == 2 && attr_len == CPROTECT_V2_LENGTH)
				{
					printf("Found major version 2\n");
					if(!EMF_decrypt_file_blocks(emf, file, cprotect_xattr->persistent_key, cprotect_xattr->persistent_class))
					{
						//TODO HAX: update cprotect xattr version field (bit1) to mark file as decrypted ?
						//cprotect_xattr->version |= 1;
						//setAttribute(volume, file->fileID, "com.apple.system.cprotect", (uint8_t*) cprotect_xattr, CPROTECT_V2_LENGTH);
					}
				} else if (cprotect_xattr->xattr_major_version == 4 && attr_len == CPROTECT_V4_LENGTH) {
					printf("Found major version 4\n");
				} else if (cprotect_xattr->xattr_major_version == 5) {
					printf("Found version 5 cprotect extended attribute\n");
					// just dump cprotect content and unwrap manually, then decrypt file blocks with LwVM key.
					uint16_t keylen = cprotect_xattr->key_len;
					uint8_t wrappedKey[keylen];
					memcpy(wrappedKey, cprotect_xattr->persistent_key, keylen);
					printf("Wrapped per-file key: ");
					printHex(wrappedKey, keylen);
					printf("File protection class: %d\n", cprotect_xattr->persistent_class);
					if(!EMF_decrypt_file_blocks(emf, file, cprotect_xattr->persistent_key, cprotect_xattr->persistent_class))
					{
						printf("Success!\n");
						//TODO HAX: update cprotect xattr version field (bit1) to mark file as decrypted ?
						/*cprotect_xattr->xattr_major_version |= 1;
						setAttribute(emf->volume, file->fileID, "com.apple.system.cprotect", (uint8_t*) cprotect_xattr, CPROTECT_V2_LENGTH);*/
					}
					break;
				} else if (cprotect_xattr->xattr_major_version & 1) {
					printf("file already decrypted by this tool\n");
				} else {
					fprintf(stderr, "Unknown cprotect xattr version/length : %x/%zx\n", cprotect_xattr->xattr_major_version, attr_len);
				}
			} else {
				fprintf(stderr, "Invalid cprotect attribute for filename: %s\n", name);
			}
		}
		
		free(name);
		list = list->next;
	}
	releaseCatalogRecordList(theList);
}

/* HFS+ Volume structure
typedef struct {
	io_func* image; disk image
	HFSPlusVolumeHeader* volumeHeader; block size, created time, catalog/extents location

	BTree* extentsTree; tracks blocks belonging to files
	BTree* catalogTree; file hierarchy
	BTree* attrTree;
	io_func* allocationFile;
	HFSCatalogNodeID metadataDir;
} Volume;
*/

int main(int argc, const char *argv[]) {
	io_func* io;
	Volume* volume;

	TestByteOrder();
	
	if(argc < 2) {
		printf("usage: %s <image-file>\n", argv[0]);
		return 0;
	}
	
	io = openFlatFile(argv[1]);

	if(io == NULL) {
		fprintf(stderr, "error: Cannot open image-file.\n");
		return 1;
	}
	printf("Parsing volume...\n");
	// Parse volume from image
	volume = openVolume(io); 
	if(volume == NULL) {
		fprintf(stderr, "error: Cannot open volume.\n");
		CLOSE(io);
		return 1;
	}
	printf("WARNING ! This tool will modify the hfs image and possibly wreck it if something goes wrong !\n" 
			"Make sure to backup the image before proceeding\n");
	printf("Press a key to continue or CTRL-C to abort\n");
	getchar();

	char* dir = dirname((char*)argv[1]);

	//EMFInfo* emf = EMF_init(volume, dir);
	LwVMInfo *lwvm = LwVM_init(volume, dir);
	if(lwvm != NULL)
	{
		printf("Decrypting starting from root folder...\n");
		// Start from the root folder ID=2
		EMF_decrypt_folder(lwvm, kHFSRootFolderID);
	}
	printf("Block size: %d\n", lwvm->volume->volumeHeader->blockSize);
	closeVolume(volume);
	CLOSE(io);
	
	return 0;
}
