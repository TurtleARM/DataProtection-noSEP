#!/bin/zsh
gcc -F /Applications/Xcode8.3.3.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/System/Library/Frameworks/ -framework IOKit -framework CoreFoundation -I/Users/turtlearm/Desktop/iOS_stuff/headers -I/Users/turtlearm/Desktop/iOS_stuff/DataProtection/kernel_tools  -mthumb -arch armv7 -isysroot /Applications/Xcode8.3.3.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS10.3.sdk -o LockerManager dp/ramdisk_tools/bsdcrypto/*.c dp/ramdisk_tools/IOAESAccelerator.c dp/ramdisk_tools/ttbthingy.c dp/ramdisk_tools/util.c dp/ramdisk_tools/kernel_patcher.c kernel_tools/*.c LockerManager.c IOKit.c AppleEffaceableStorage.c dp/ramdisk_tools/AppleKeyStore_kdf.c
if [ $? -eq 1 ]
then
   exit 1
fi
./ldid2 -Stfpent.xml LockerManager
sshpass -p alpine sftp root@192.168.10.188 <<EOF
rm /var/test/LockerManager
put LockerManager /var/test/LockerManager
exit
EOF
