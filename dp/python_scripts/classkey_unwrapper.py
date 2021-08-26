from crypto.PBKDF2 import PBKDF2
from util.bplist import BPlistReader
from crypto.aeswrap import AESUnwrap
from crypto.aes import AESdecryptCBC

def getPasscodekeyFromPasscode(passcode): # salt
    return PBKDF2(passcode, b"\x1c\x84\xce\x34\xe5\xa5\x3f\xa7\xeb\xde\xce\x2d\xce\x4c\xb1\x75\x35\xcd\x6f\x40",
                  iterations=1).read(32)

def printAsBytes(str):
    print('\\x' + '\\x'.join(x.encode('hex') for x in str))

def unlockKey(passcodekey, wpky):
    k = AESUnwrap(passcodekey, wpky)
    if not k:
        print("AESUnwrap retuned empty value")
        exit(-1)
    return AESdecryptCBC(k, deviceKey)

intermediarykey = getPasscodekeyFromPasscode("0255") # keep deriving on device to get passcodekey...
# Run LockerManager.c on the device and paste the result in the "passcodekey" variable

wpky1 = b"\x69\x26\xf2\x28\xf7\x4a\x0b\x13\x0f\x70\x3d\x40\x1e\xc7\x06\x9d\xa5\x8b\x09\x47\x88\x6a\xe2\x0d\xc2\xaa\x5f\xe6\xd1\x5b\xb1\x37\xdd\xc9\x1d\x5c\x26\xe6\x9b\x7e"
wpky3 = b"\x9f\xca\xc0\xaf\xec\xbf\xff\x87\xcb\xc7\x4f\xa8\xe7\xd4\x38\xbd\x28\xa9\x51\x25\xbf\x6e\x1a\xe8\x8d\x8f\x78\xd9\x01\x4d\x1d\x27\x68\x4b\x86\x14\xd6\xcd\xe3\x6f"
wpky2 = b"\x3b\xde\x91\xc3\x28\x27\x98\x48\xa3\xba\x02\xc6\xf2\x52\x46\x36\xfa\x29\xa8\xd5\x9f\x42\x30\x3d\x35\x6b\x30\xff\xd2\xc0\xd1\xb8\x6c\x15\x54\x55\xd8\x43\xfa\xef"
wpbky = b"\x1e\x4e\xa1\xdf\xdf\x2d\x80\xa6\xbc\x7c\x10\x1e\x36\x5a\xd7\x67\x38\x55\xf3\xc7\x13\xe6\x7d\x20\xb9\x50\xda\x31\xda\xab\xac\x4d"
passcodekey = b"\x6C\xED\xFA\xA8\x7E\x3C\xE0\x92\xEA\x2D\xB0\xCF\xB6\x56\x90\xC1\xA7\xA5\x5D\x78\x54\xDE\x47\xCF\xEA\x28\x8B\x35\x0E\xC1\xBF\x45"
key835 = "C916AD4DB2D08FC5BD686F358B6E99F1"
deviceKey = key835.decode('hex')
# C1
k1 = unlockKey(passcodekey, wpky1)
print("Class 1 Data Protection Key: ")
printAsBytes(k1)

# C3
k3 = unlockKey(passcodekey, wpky3)
print("Class 3 Data Protection Key: ")
printAsBytes(k3)

# C2
k2 = unlockKey(passcodekey, wpky2)
print("Class 2 Private Key: ")
printAsBytes(k2)

print("Class 2 Public Key is already unwrapped")