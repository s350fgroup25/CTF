# coding=utf-8
import binascii
a = []
for i in range(641):
    k=binascii.hexlify(bytes(str(i).encode()))+b"2d61646d696e"
    a.append(k.decode())
with open ("1.txt","w") as f:
    for i in a:
        f.write(i+"\n")
