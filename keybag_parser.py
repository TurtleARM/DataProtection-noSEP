import sys

if len(sys.argv) < 3:
    print("Usage: ./python_keyparser.py filename dpclass")
    exit(-1)
filename = sys.argv[1]
dpclass = bytes([int(sys.argv[2])])
with open(filename, "rb") as f:
    data = f.read()
    # SALT
    saltposition = data.find(b"\x53\x41\x4C\x54")
    if saltposition < 0:
        print("KDF salt not found")
        exit(-1)
    salt = data[saltposition + 8: saltposition + 28]
    formatted = ""
    for byte in salt:
        formatted += hex(byte).replace("0x", "\\x")
    print("Salt: {}".format(formatted))
    # Number of iterations
    iterposition = data.find(b"\x49\x54\x45\x52")
    if iterposition < 0:
        print("ITER not found")
        exit(-1)
    iter = data[iterposition + 8: iterposition + 12]
    iternum = int.from_bytes(iter, byteorder='big', signed=False)
    print("Number of iterations: {}".format(iternum))
    # DP 
    if sys.argv[2] != "2":
        position = data.find(b"\x43\x4C\x41\x53\x00\x00\x00\x04\x00\x00\x00" + dpclass)
        if position < 0:
            print("Data Protection Key not found")
            exit(-1)
        print("Position: ", position)
        classkey = data[position + 44: position + 84]
        formatted = ""
        for byte in classkey:
            formatted += hex(byte).replace("0x", "\\x")
        print("Wrapped class {} key: {}".format(sys.argv[2], formatted))
    else:
        formatted = ""
        formattedpub = ""
        position = data.find(b"\x50\x42\x4B\x59")
        if position < 0:
            print("Public key not found")
            exit(-1)
        print("Position: ", position)
        pubkey = data[position + 8: position + 40]
        position = data.find(b"\x43\x4C\x41\x53\x00\x00\x00\x04\x00\x00\x00" + dpclass)
        if position < 0:
            print("Private key not found")
            exit(-1)
        privkey = data[position + 44: position + 84]
        print("Position: ", position)
        for byte in pubkey:
            formattedpub += hex(byte).replace("0x", "\\x")
        for byte in privkey:
            formatted += hex(byte).replace("0x", "\\x")
        print("Private Key: {}".format(formatted))
        print("Public Key: {}".format(formattedpub))