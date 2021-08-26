from construct import Struct, ULInt16, ULInt32, String
from construct.macros import ULInt64, Padding, If
from crypto.aes import AESencryptCBC, AESdecryptCBC
from crypto.curve25519 import curve25519
from hfs import HFSVolume, HFSFile
from hashlib import sha256
#from keystore.keybag import Keybag  remove keybag parsing as dependency
from structs import HFSPlusVolumeHeader, kHFSPlusFileRecord, getString, \
    kHFSRootParentID
from util import search_plist
from util.bruteforce import loadKeybagFromVolume
import hashlib
import os
import plistlib
import struct
from crypto.aeswrap import AESUnwrap

import struct

"""
iOS >= 4 raw images
http://opensource.apple.com/source/xnu/xnu-1699.22.73/bsd/hfs/hfs_cprotect.c
http://opensource.apple.com/source/xnu/xnu-1699.22.73/bsd/sys/cprotect.h
"""

#  XNU 3257/8
#  typedef struct cprotect_xattr_v5 {
# 	uint16_t			xattr_major_version;
# 	uint16_t			xattr_minor_version;
# 	uint32_t			flags;
# 	uint32_t			persistent_class;
# 	uint32_t			key_os_version;
# 	uint16_t			key_revision;
# 	uint16_t			key_len;

# 	// 20 bytes to here

# 	// Variable length from here
# 	uint8_t				persistent_key[CP_MAXWRAPPEDKEYSIZE];

# 	// Wouldn't be necessary if xattr routines returned just what we ask for
# 	uint8_t				spare[512];
# } cprotect_xattr_v5;

cprotect_xattr_v5 = Struct("cprotect_xattr_v5",
    ULInt16("xattr_major_version"),
    ULInt16("xattr_minor_version"),
    ULInt32("flags"),
    ULInt32("persistent_class"),
    ULInt32("key_os_version"),
    ULInt16("key_revision"),
    ULInt16("key_len"),
    #If(lambda ctx: ctx["xattr_major_version"] >= 5, Padding(20)),
    String("persistent_key", length=lambda ctx: ctx["key_len"])
)

cp_root_xattr = Struct("cp_root_xattr",
    ULInt16("major_version"),
    ULInt16("minor_version"),
    ULInt64("flags"),
    ULInt32("reserved1"),
    ULInt32("reserved2"),
    ULInt32("reserved3"),
    ULInt32("reserved4")
)

cprotect_xattr = Struct("cprotect_xattr",
    ULInt16("xattr_major_version"),
    ULInt16("xattr_minor_version"),
    ULInt32("flags"),
    ULInt32("persistent_class"),
    ULInt32("key_size"),
    If(lambda ctx: ctx["xattr_major_version"] >= 4, Padding(20)),
    String("persistent_key", length=lambda ctx: ctx["key_size"])
)
NSProtectionNone = 4

PROTECTION_CLASSES={
    1:"NSFileProtectionComplete",
    2:"NSFileProtectionCompleteUnlessOpen",
    3:"NSFileProtectionCompleteUntilFirstUserAuthentication",
    4:"NSFileProtectionNone",
    5:"NSFileProtectionRecovery?"
}

#HAX: flags set in finderInfo[3] to tell if the image was already decrypted
FLAG_DECRYPTING = 0x454d4664  #EMFd big endian
FLAG_DECRYPTED = 0x454d4644  #EMFD big endian

class EMFFile(HFSFile):
    def __init__(self, volume, hfsplusfork, fileID, filekey, deleted=False):
        super(EMFFile,self).__init__(volume, hfsplusfork, fileID, deleted)
        self.filekey = filekey
        self.ivkey = None
        self.decrypt_offset = 0
        if volume.cp_major_version >= 4:
            self.ivkey = hashlib.sha1(filekey).digest()[:16]

    def processBlock(self, block, lba):
        iv = self.volume.ivForLBA(lba)
        ciphertext = AESencryptCBC(block, self.volume.emfkey, iv)
        if not self.ivkey:
            clear = AESdecryptCBC(ciphertext, self.filekey, iv)
        else:
            clear = ""
            for i in xrange(len(block)/0x1000):
                iv = self.volume.ivForLBA(self.decrypt_offset, False)
                iv = AESencryptCBC(iv, self.ivkey)
                clear += AESdecryptCBC(ciphertext[i*0x1000:(i+1)*0x1000], self.filekey,iv)
                self.decrypt_offset += 0x1000
        return clear
    
    def decryptFile(self):
        self.decrypt_offset = 0
        bs = self.volume.blockSize
        for extent in self.extents:
            for i in xrange(extent.blockCount):
                lba = extent.startBlock+i
                data = self.volume.readBlock(lba)
                if len(data) == bs:
                    clear = self.processBlock(data, lba)
                    self.volume.writeBlock(lba, clear)


class EMFVolume(HFSVolume):
    def __init__(self, bdev, device_infos, **kwargs):
        super(EMFVolume,self).__init__(bdev, **kwargs)
        volumeid = self.volumeID().encode("hex")

        if not device_infos:
            dirname = os.path.dirname(bdev.filename)
            # just fill the dict
            device_infos = search_plist(dirname, {"dataVolumeUUID":volumeid})
            if not device_infos:
                raise Exception("Missing keyfile")
        try:
            self.emfkey = None
            # insert EMF key in the right spot and in the right format
            # device_infos["DKey"] has to contain DKEY
            if device_infos.has_key("EMF"):
                self.emfkey = device_infos["EMF"].decode("hex")
            self.lbaoffset = device_infos["dataVolumeOffset"]
            # no need for this bs
            #self.keybag = Keybag.createWithPlist(device_infos)
        except:
            raise #Exception("Invalid keyfile")
        
        self.decrypted = (self.header.finderInfo[3] == FLAG_DECRYPTED) 
        rootxattr =  self.getXattr(kHFSRootParentID, "com.apple.system.cprotect")
        self.cp_major_version = None
        self.cp_root = None
        if rootxattr == None:
            print "(No root com.apple.system.cprotect xattr)"
        else:
            self.cp_root = cprotect_xattr_v5.parse(rootxattr)
            ver = self.cp_root.xattr_major_version
            print "cprotect version : %d" % ver
            assert self.cp_root.xattr_major_version == 2 or self.cp_root.xattr_major_version == 4 or  self.cp_root.xattr_major_version == 5
            self.cp_major_version = self.cp_root.xattr_major_version
        #self.keybag = loadKeybagFromVolume(self, device_infos)
            
    def ivForLBA(self, lba, add=True):
        iv = ""
        if add:
            lba = lba + self.lbaoffset
        lba &= 0xffffffff
        for _ in xrange(4):
            if (lba & 1):
                lba = 0x80000061 ^ (lba >> 1);
            else:
                lba = lba >> 1;
            iv += struct.pack("<L", lba)
        return iv
    
    def unwrapCurve25519(self, persistent_key):
        assert len(persistent_key) == 0x48
        mysecret = "a63601a12737a0ceadaa9b517bb9e3c6c0c16dc3f6259fdecfec14750d293b3b".decode('hex')
        mypublic = "1e4ea1dfdf2d80a6bc7c101e365ad7673855f3c713e67d20b950da31daabac4d".decode('hex')
        hispublic = persistent_key[:32]
        shared = curve25519(mysecret, hispublic)
        md = sha256('\x00\x00\x00\x01' + shared + hispublic + mypublic).digest()
        return AESUnwrap(md, persistent_key[32:])

    def getFileKeyForCprotect(self, cp):
        if self.cp_major_version == None:
            self.cp_major_version = struct.unpack("<H", cp[:2])[0]
        cprotect = cprotect_xattr_v5.parse(cp)
        #return self.keybag.unwrapKeyForClass(cprotect.persistent_class, cprotect.persistent_key) no need for keybag
        if cprotect.persistent_class == 4: # DKey
            ck = "90562A56314E2DC685AFFCC0767467EA28778A6206CF5107347140EA1508C835".decode('hex') #self.classKeys[clas]["KEY"]
        elif cprotect.persistent_class == 1:
            ck = "84A67F7691FD733626527394DD87B4DD8F991A34EAB07EA845FCF2F443DF3403".decode('hex')
        elif cprotect.persistent_class == 3:
            ck = "F805F732A4BE479B65FBCAAAE503308F4BEA88F16E7249E55A7984D00FCC8D27".decode('hex')
        elif cprotect.persistent_class == 2: # Asymmetric encryption: privkey only available after first unlock
            return self.unwrapCurve25519(cprotect.persistent_key)
        else:
            print "Skipping unknown class file... :("
            return 0
        if len(cprotect.persistent_key) == 0x28:
            return AESUnwrap(ck, cprotect.persistent_key)
        else:
            print "Wrong key length"
            return 0

    def getFileKeyForFileId(self, fileid):
        cprotect = self.getXattr(fileid, "com.apple.system.cprotect")
        if cprotect == None:
            return None
        return self.getFileKeyForCprotect(cprotect)

    def readFile_old_api(self, path, outFolder="./", returnString=False):
        k,v = self.catalogTree.getRecordFromPath(path)
        if not v:
            print "File %s not found" % path
            return
        assert v.recordType == kHFSPlusFileRecord
        cprotect = self.getXattr(v.data.fileID, "com.apple.system.cprotect")
        if cprotect == None or not self.cp_root or self.decrypted:
            #print "cprotect attr not found, reading normally"
            return super(EMFVolume, self).readFile(path, returnString=returnString)
        filekey = self.getFileKeyForCprotect(cprotect)
        if not filekey:
            print "Cannot unwrap file key for file %s protection_class=%d" % (path, cprotect_xattr.parse(cprotect).persistent_class)
            return
        f = EMFFile(self, v.data.dataFork, v.data.fileID, filekey)
        if returnString:
            return f.readAllBuffer()
        output = open(outFolder + os.path.basename(path), "wb")
        f.readAll(output)
        output.close()
        return True

    def readFileByRecord(self, key, record, output):
        assert record.recordType == kHFSPlusFileRecord
        cprotect = self.getXattr(record.data.fileID, "com.apple.system.cprotect")
        if cprotect == None or not self.cp_root or self.decrypted:
            #print "cprotect attr not found, reading normally"
            return super(EMFVolume, self).readFileByRecord(key, record, output)
        filekey = self.getFileKeyForCprotect(cprotect)
        if not filekey:
            print "Cannot unwrap file key for file %d protection_class=%d" % (record.data.fileID, cprotect_xattr.parse(cprotect).persistent_class)
            return
        f = EMFFile(self, record.data.dataFork, record.data.fileID, filekey)
        f.readAll(output)
        return True
    
    def flagVolume(self, flag):
        self.header.finderInfo[3] = flag
        h = HFSPlusVolumeHeader.build(self.header)
        return self.bdev.write(0x400, h)
        
    def decryptAllFiles(self):
        if self.header.finderInfo[3] == FLAG_DECRYPTING:
            print "Volume is half-decrypted, aborting (finderInfo[3] == FLAG_DECRYPTING)"
            return
        elif self.header.finderInfo[3] == FLAG_DECRYPTED:
            print "Volume already decrypted (finderInfo[3] == FLAG_DECRYPTED)"
            return
        self.failedToGetKey = []
        self.notEncrypted = []
        self.decryptedCount = 0
        self.flagVolume(FLAG_DECRYPTING)
        self.catalogTree.traverseLeafNodes(callback=self.decryptFile)
        self.flagVolume(FLAG_DECRYPTED)
        print "Decrypted %d files" % self.decryptedCount
        print "Failed to unwrap keys for : ", self.failedToGetKey
        print "Not encrypted files : %d" % len(self.notEncrypted)

    def decryptFile(self, k,v):
        if v.recordType == kHFSPlusFileRecord:
            filename = getString(k).encode("utf-8")
            cprotect = self.getXattr(v.data.fileID, "com.apple.system.cprotect")
            if not cprotect:
                self.notEncrypted.append(filename)
                return
            fk = self.getFileKeyForCprotect(cprotect)
            if not fk:
                self.failedToGetKey.append(filename)
                return
            print "Decrypting", filename
            f = EMFFile(self, v.data.dataFork, v.data.fileID, fk)
            f.decryptFile()
            self.decryptedCount += 1

    def list_protected_files(self):
        self.protected_dict = {}
        self.xattrTree.traverseLeafNodes(callback=self.inspectXattr)
        for k in self.protected_dict.keys():
            print k
            for v in self.protected_dict[k]: print "\t",v
            print ""
            
    def inspectXattr(self, k, v):
        if getString(k) == "com.apple.system.cprotect" and k.fileID != kHFSRootParentID:
            c = cprotect_xattr.parse(v.data)
            if c.persistent_class != NSProtectionNone:
                #desc = "%d %s" % (k.fileID, self.getFullPath(k.fileID))
                desc = "%s" % self.getFullPath(k.fileID)
                self.protected_dict.setdefault(PROTECTION_CLASSES.get(c.persistent_class),[]).append(desc)
                #print k.fileID, self.getFullPath(k.fileID), PROTECTION_CLASSES.get(c.persistent_class)
