#!/usr/bin/python3
import sys

def str_to_hex(s):
    hexstr = []

    for i in range(0, len(s)):
        hexstr.append(hex(ord(s[i]))[2:]) 
    res = "0x"
    res += "".join(hexstr)
    return res 

#s = "/bin//sh" #the extra slash aligns string to 8 bytes and is effectivley ignored
#h = str_to_hex(s)

#our string needs to be in little endian, so the bytes need to be reversed

def rev_hex_str(h):
    rev_str = ""

    h = h[2:]
    for i in range(len(h)-1, -1, -2):
        rev_str += f"{h[i-1]}{h[i]}"
    rev_str = "0x" + rev_str
    return rev_str

#print(rev_hex_str(h))  #little endian byte order

arg = sys.argv[1]
if len(sys.argv) < 2:
    print("Usage: %s [string]" %__name__)
h = str_to_hex(arg)
rh = rev_hex_str(h)
print(rh)