#!/usr/bin/python
from optparse import OptionParser
from hfs.emf import EMFVolume
from util.bdev import FileBlockDevice
import plistlib

# Dkey: 90 56 2A 56 31 4E 2D C6 85 AF FC C0 76 74 67 EA 28 77 8A 62 06 CF 51 07 34 71 40 EA 15 08 C8 35
# Class 1 Key: 18 F1 81 F6 B5 44 A7 BC 8A 10 8E 49 53 50 14 A5 1F 34 22 AF 6D EE F8 97 C6 9C DD 10 CD AA 98 80
# EMF Key: B6 EE E3 0D 53 65 C4 8C 3B B0 C8 17 39 17 D2 D8 DF DC F6 9C AE 32 A8 DD F3 8B 8C D8 09 86 91 3F

def main():
    parser = OptionParser(usage="emf_decrypter.py disk_image.bin")
    parser.add_option("-w", "--nowrite", dest="write", action="store_false", default=True,
                  help="disable modifications of input file, for testing")
    (options, args) = parser.parse_args()
    if len(args) < 1:
        parser.print_help()
        return
    device_infos = {"EMF": "B6EEE30D5365C48C3BB0C8173917D2D8DFDCF69CAE32A8DDF38B8CD80986913F", "DKEY": "90562A56314E2DC685AFFCC0767467EA28778A6206CF5107347140EA1508C835", 
    "dataVolumeOffset": 675840}
    
    p = FileBlockDevice(args[0], 0, options.write)
    v = EMFVolume(p, device_infos)
    #if not v.keybag.unlocked:
    #    print "Keybag locked, protected files won't be decrypted, continue anyway ?"
    #    if raw_input() == "n":
    #        return
    if options.write:
        print "WARNING ! This tool will modify the hfs image and possibly wreck it if something goes wrong !"
        print "Make sure to backup the image before proceeding"
        print "You can use the --nowrite option to do a dry run instead"
    else:
        print "Test mode : the input file will not be modified"
    print "Press a key to continue or CTRL-C to abort"
    raw_input()
    v.decryptAllFiles()

if __name__ == "__main__": 
    main()
