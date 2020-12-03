
from Crypto.Cipher import AES
from Crypto.Cipher import DES
import hashlib
import binascii, os, random, struct
from tkinter import filedialog
import tkinter

'''
Padding 
-ECB : O 
-CBC : O 
-OFB : X 
-CFB : X 
-CTR : X 
'''
# file의 hash값을 계산하는 함수
def hash_file(filename):
    h = hashlib.sha256()
    with open(filename,'rb') as file:
        buffer = 0
        while buffer != b'':
            buffer = file.read(1024*64)
            h.update(buffer)
    return h.hexdigest()

def encrypt_ECB_bytes(blkcipher, key, iv, src_bytes):
    # PKCS7 Padding
    pad_val = 16 - len(src_bytes) % 16
    pad = pad_val.to_bytes(1, byteorder='big', signed=True) * pad_val
    src_bytes += pad

    if blkcipher == 0:
        cipher = AES.new(key, AES.MODE_ECB)
    elif blkcipher == 1:
        cipher = DES.new(key, DES.MODE_ECB)
    
    return cipher.encrypt(src_bytes)

def decrypt_ECB_bytes(blkcipher, key, iv, src_bytes):

    if blkcipher == 0:
        cipher = AES.new(key, AES.MODE_ECB)
    elif blkcipher == 1:
        cipher = DES.new(key, DES.MODE_ECB)
    
    dst_bytes = cipher.decrypt(src_bytes)

    pad_len = dst_bytes[len(dst_bytes)-1]
    return dst_bytes[:len(dst_bytes)-pad_len]

def xor(input_bytes, xor_bytes):
    index = 0
    output_bytes = b''
    for byte in input_bytes:
        if index >= len(xor_bytes):
            index = 0
        output_bytes += bytes([byte ^ xor_bytes[index]])
        index += 1
    return output_bytes

def encrypt_CBC_bytes(blkcipher, key, iv, src_bytes):
    # PKCS7 Padding
    pad_val = 16 - len(src_bytes) % 16
    pad = pad_val.to_bytes(1, byteorder='big', signed=True) * pad_val
    src_bytes += pad

    dst_bytes = b''
    nb_blocks = (int)(len(src_bytes) / 16)

    if blkcipher == 0:
        cipher = AES.new(key, AES.MODE_ECB)
    elif blkcipher == 1:
        cipher = DES.new(key, DES.MODE_ECB)

    for i in range(nb_blocks):
        enc = xor(src_bytes[i * 16:(i + 1) * 16], iv) 
        iv = cipher.encrypt(enc) 
        dst_bytes += iv

    return dst_bytes

def decrypt_CBC_bytes(blkcipher, key, iv, src_bytes):
    
    if blkcipher == 0:
        cipher = AES.new(key, AES.MODE_ECB)
    elif blkcipher == 1:
        cipher = DES.new(key, DES.MODE_ECB)
    
    dst_bytes = b''
    nb_blocks = (int)(len(src_bytes) / 16)

    for i in range(nb_blocks):
        output = cipher.decrypt(src_bytes[i * 16:(i + 1) * 16]) 
        dec = xor(output, iv) 
        iv = src_bytes[i * 16:(i + 1) * 16]
        dst_bytes += dec
    
    pad_len = dst_bytes[len(dst_bytes)-1]
    
    return dst_bytes[:len(dst_bytes)-pad_len]

def encrypt_OFB_bytes(blkcipher, key, iv, src_bytes):
    dst_bytes = b''
    nb_blocks = (int)(len(src_bytes) / 16)
    
    if blkcipher == 0:
        cipher = AES.new(key, AES.MODE_ECB)
    elif blkcipher == 1:
        cipher = DES.new(key, DES.MODE_ECB)

    for i in range(nb_blocks+1):
        iv = cipher.encrypt(iv)
        dst_bytes += xor(src_bytes[i * 16:(i + 1) * 16], iv) 
    
    return dst_bytes[:len(src_bytes)]

def decrypt_OFB_bytes(blkcipher, key, iv, src_bytes):
    dst_bytes = b''
    nb_blocks = (int)(len(src_bytes) / 16)
    
    if blkcipher == 0:
        cipher = AES.new(key, AES.MODE_ECB)
    elif blkcipher == 1:
        cipher = DES.new(key, DES.MODE_ECB)

    for i in range(nb_blocks+1):
        iv = cipher.encrypt(iv) 
        tmp = xor(src_bytes[i * 16:(i + 1) * 16], iv) 
        dst_bytes += tmp
   
    return dst_bytes[:len(src_bytes)]

def encrypt_CFB_bytes(blkcipher, key, iv, src_bytes):
    dst_bytes = b''
    tmp = b''
    nb_blocks = (int)(len(src_bytes) / 16)
    
    if blkcipher == 0:
        cipher = AES.new(key, AES.MODE_ECB)
    elif blkcipher == 1:
        cipher = DES.new(key, DES.MODE_ECB)

    for i in range(nb_blocks+1):
        tmp = cipher.encrypt(iv) 
        iv = xor(src_bytes[i * 16:(i + 1) * 16], tmp) 
        dst_bytes += iv
   
    return dst_bytes[:len(src_bytes)]

def decrypt_CFB_bytes(blkcipher, key, iv, src_bytes):
    dst_bytes = b''
    nb_blocks = (int)(len(src_bytes) / 16)
    
    if blkcipher == 0:
        cipher = AES.new(key, AES.MODE_ECB)
    elif blkcipher == 1:
        cipher = DES.new(key, DES.MODE_ECB)

    for i in range(nb_blocks+1):
        tmp = cipher.encrypt(iv)
        dst_bytes += xor(src_bytes[i * 16:(i + 1) * 16], tmp) 
        iv = src_bytes[i * 16:(i + 1) * 16]
   

    return dst_bytes[:len(src_bytes)]

def encrypt_CTR_bytes(blkcipher, key, iv, src_bytes):
    dst_bytes = b''
    tmp = b''
    nb_blocks = (int)(len(src_bytes) / 16)

    if blkcipher == 0:
        cipher = AES.new(key, AES.MODE_ECB)
    elif blkcipher == 1:
        cipher = DES.new(key, DES.MODE_ECB)
    
    for i in range(nb_blocks+1):
        cnt = bytes(i)
        print(binascii.hexlify((iv + cnt)[:len(iv)]))
        tmp = cipher.encrypt((iv + cnt)[:len(iv)]) 
        print(binascii.hexlify(tmp))
        iv = xor(src_bytes[i * 16:(i + 1) * 16], tmp) 
        dst_bytes += iv

    return cipher.encrypt(src_bytes)
    
# Sample code: File Encryption
#key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c") #ECB, CBC AES
key = bytes.fromhex("0123456789abcdef") #DES


#iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f") #ECB, CBC AES
iv = bytes.fromhex("1234567890abcdef") #DES
#iv = bytes.fromhex("0000000000000000") 


#key랑 iv byte로 고정
root = tkinter.Tk()
root.withdraw()
#뭔 lightweight를 위한 호출이래요

# Sample code: HexString Encryption
# AES : 0
# DES : 1
#msg = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710") #ECB, CBC AES
#msg = bytes.fromhex("4e6f772069732074") #ECB, CBC DES
#msg = bytes.fromhex("68652074696d6520")
msg = bytes.fromhex("4e6f7720697320746865")

print (binascii.hexlify(msg))
#dst = encrypt_ECB_bytes(0, key, iv, msg)
#dst = encrypt_ECB_bytes(1, key, iv, msg)

#dst = encrypt_CBC_bytes(0, key, iv, msg)
#dst = encrypt_CBC_bytes(1, key, iv, msg)

#dst = encrypt_OFB_bytes(0, key, iv, msg)
#dst = encrypt_OFB_bytes(1, key, iv, msg)

#dst = encrypt_CFB_bytes(0, key, iv, msg)
dst = encrypt_CFB_bytes(1, key, iv, msg)

#dst = encrypt_CTR_bytes(0, key, iv, msg)
#dst = encrypt_CTR_bytes(1, key, iv, msg)

print (binascii.hexlify(dst))
#dst2 = decrypt_ECB_bytes(0, key, iv, dst)
#dst2 = decrypt_ECB_bytes(1, key, iv, dst)

#dst2 = decrypt_CBC_bytes(0, key, iv, dst)
#dst2 = decrypt_CBC_bytes(1, key, iv, dst)

#dst2 = decrypt_OFB_bytes(0, key, iv, dst)
#dst2 = decrypt_OFB_bytes(1, key, iv, dst)

#dst2 = decrypt_CFB_bytes(0, key, iv, dst)
dst2 = decrypt_CFB_bytes(1, key, iv, dst)

print (binascii.hexlify(dst2))
#testvector = DES.new(key, DES.MODE_OFB, iv)
#print (DES.new(key, DES.MODE_CBC, iv))

print (msg == dst2)


