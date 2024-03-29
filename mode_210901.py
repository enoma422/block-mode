
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

def encrypt_ECB_bytes(blkcipher, key, iv, src_bytes):

    if blkcipher == 0:
        cipher = AES.new(key, AES.MODE_ECB)
        # PKCS7 Padding
        pad_val = 16 - len(src_bytes) % 16
        pad = pad_val.to_bytes(1, byteorder='big', signed=True) * pad_val
        src_bytes += pad
    elif blkcipher == 1:
        cipher = DES.new(key, DES.MODE_ECB)
        # PKCS7 Padding
        pad_val = 8 - len(src_bytes) % 8
        pad = pad_val.to_bytes(1, byteorder='big', signed=True) * pad_val
        src_bytes += pad
    
    return cipher.encrypt(src_bytes)

def decrypt_ECB_bytes(blkcipher, key, iv, src_bytes):

    if blkcipher == 0:
        cipher = AES.new(key, AES.MODE_ECB)
    elif blkcipher == 1:
        cipher = DES.new(key, DES.MODE_ECB)
    
    dst_bytes = cipher.decrypt(src_bytes) 

    pad_len = dst_bytes[len(dst_bytes)-1]

    return dst_bytes[:len(dst_bytes)-pad_len]

#ECB를 제외한 mode는 xor이 필요
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
    dst_bytes = b''

    if blkcipher == 0:
        cipher = AES.new(key, AES.MODE_ECB)
        nb_blocks = (int)(len(src_bytes) / 16)
        # PKCS7 Padding
        pad_val = 16 - len(src_bytes) % 16
        pad = pad_val.to_bytes(1, byteorder='big', signed=True) * pad_val
        src_bytes += pad

        for i in range(nb_blocks+1):
            enc = xor(src_bytes[i * 16:(i + 1) * 16], iv) 
            iv = cipher.encrypt(enc) 
            dst_bytes += iv

    elif blkcipher == 1:
        cipher = DES.new(key, DES.MODE_ECB)
        nb_blocks = (int)(len(src_bytes) / 8)
        # PKCS7 Padding
        pad_val = 8 - len(src_bytes) % 8
        pad = pad_val.to_bytes(1, byteorder='big', signed=True) * pad_val
        src_bytes += pad

        for i in range(nb_blocks+1):
            enc = xor(src_bytes[i * 8:(i + 1) * 8], iv) 
            iv = cipher.encrypt(enc) 
            dst_bytes += iv

    return dst_bytes

def decrypt_CBC_bytes(blkcipher, key, iv, src_bytes):
    dst_bytes = b''

    if blkcipher == 0:
        cipher = AES.new(key, AES.MODE_ECB)
        nb_blocks = (int)(len(src_bytes) / 16)

        for i in range(nb_blocks+1):
            output = cipher.decrypt(src_bytes[i * 16:(i + 1) * 16]) 
            dec = xor(output, iv) 
            iv = src_bytes[i * 16:(i + 1) * 16]
            dst_bytes += dec

    elif blkcipher == 1:
        cipher = DES.new(key, DES.MODE_ECB)
        nb_blocks = (int)(len(src_bytes) / 8)

        for i in range(nb_blocks+1):
            output = cipher.decrypt(src_bytes[i * 8:(i + 1) * 8]) 
            dec = xor(output, iv) 
            iv = src_bytes[i * 8:(i + 1) * 8]
            dst_bytes += dec
         
    pad_len = dst_bytes[len(dst_bytes)-1]
    return dst_bytes[:len(dst_bytes)-pad_len]

def encrypt_OFB_bytes(blkcipher, key, iv, src_bytes):
    dst_bytes = b''
    
    if blkcipher == 0:
        cipher = AES.new(key, AES.MODE_ECB)
        nb_blocks = (int)(len(src_bytes) / 16)

        for i in range(nb_blocks+1):
            iv = cipher.encrypt(iv)
            dst_bytes += xor(src_bytes[i * 16:(i + 1) * 16], iv) 

    elif blkcipher == 1:
        cipher = DES.new(key, DES.MODE_ECB)
        nb_blocks = (int)(len(src_bytes) / 8)

        for i in range(nb_blocks+1):
            iv = cipher.encrypt(iv)
            dst_bytes += xor(src_bytes[i * 8:(i + 1) * 8], iv)

    return dst_bytes[:len(src_bytes)]

def decrypt_OFB_bytes(blkcipher, key, iv, src_bytes):
    dst_bytes = b''
    
    if blkcipher == 0:
        cipher = AES.new(key, AES.MODE_ECB)
        nb_blocks = (int)(len(src_bytes) / 16)

        for i in range(nb_blocks+1):
            iv = cipher.encrypt(iv) 
            tmp = xor(src_bytes[i * 16:(i + 1) * 16], iv) 
            dst_bytes += tmp

    elif blkcipher == 1:
        cipher = DES.new(key, DES.MODE_ECB)
        nb_blocks = (int)(len(src_bytes) / 8)

        for i in range(nb_blocks+1):
            iv = cipher.encrypt(iv) 
            tmp = xor(src_bytes[i * 8:(i + 1) * 8], iv) 
            dst_bytes += tmp
   
    return dst_bytes[:len(src_bytes)]

def encrypt_CFB_bytes(blkcipher, key, iv, src_bytes):
    dst_bytes = b''
    tmp = b''
    
    if blkcipher == 0:
        cipher = AES.new(key, AES.MODE_ECB)
        nb_blocks = (int)(len(src_bytes) / 16)

        for i in range(nb_blocks+1):
            tmp = cipher.encrypt(iv)
            iv = xor(src_bytes[i * 16:(i + 1) * 16], tmp) 
            dst_bytes += iv

    elif blkcipher == 1:
        cipher = DES.new(key, DES.MODE_ECB)
        nb_blocks = (int)(len(src_bytes) / 8)

        for i in range(nb_blocks+1):
            tmp = cipher.encrypt(iv) 
            iv = xor(src_bytes[i * 8:(i + 1) * 8], tmp)
            dst_bytes += iv

    return dst_bytes[:len(src_bytes)]

def decrypt_CFB_bytes(blkcipher, key, iv, src_bytes):
    dst_bytes = b''
    
    if blkcipher == 0:
        cipher = AES.new(key, AES.MODE_ECB)
        nb_blocks = (int)(len(src_bytes) / 16)

        for i in range(nb_blocks+1):
            tmp = cipher.encrypt(iv)
            dst_bytes += xor(src_bytes[i * 16:(i + 1) * 16], tmp) 
            iv = src_bytes[i * 16:(i + 1) * 16]

    elif blkcipher == 1:
        cipher = DES.new(key, DES.MODE_ECB)
        nb_blocks = (int)(len(src_bytes) / 8)

        for i in range(nb_blocks+1):
            tmp = cipher.encrypt(iv)
            dst_bytes += xor(src_bytes[i * 8:(i + 1) * 8], tmp) 
            iv = src_bytes[i * 8:(i + 1) * 8]

    return dst_bytes[:len(src_bytes)]

def encrypt_CTR_bytes(blkcipher, key, ctr, src_bytes):
    dst_bytes = b''
    tmp = b''

    if blkcipher == 0:
        cipher = AES.new(key, AES.MODE_ECB)
        nb_blocks = (int)(len(src_bytes) / 16)

        for i in range(nb_blocks+1):
            tmp = cipher.encrypt(ctr)
            dst_bytes += xor(src_bytes[i * 16:(i + 1) * 16], tmp) 
            ctr = int.from_bytes(ctr, byteorder='big') + 1
            ctr = ctr.to_bytes(16, byteorder='big', signed=0)

    elif blkcipher == 1:
        cipher = DES.new(key, DES.MODE_ECB)
        nb_blocks = (int)(len(src_bytes) / 8)

        for i in range(nb_blocks+1):
            tmp = cipher.encrypt(ctr) 
            dst_bytes += xor(src_bytes[i * 8:(i + 1) * 8], tmp)
            ctr = int.from_bytes(ctr, byteorder='big') + 1
            ctr = ctr.to_bytes(16, byteorder='big', signed=0)

    return dst_bytes[:len(src_bytes)]

    
def decrypt_CTR_bytes(blkcipher, key, ctr, src_bytes):
    dst_bytes = b''
    tmp = b''

    if blkcipher == 0:
        cipher = AES.new(key, AES.MODE_ECB)
        nb_blocks = (int)(len(src_bytes) / 16)

        for i in range(nb_blocks+1):
            tmp = cipher.encrypt(ctr)
            dst_bytes += xor(src_bytes[i * 16:(i + 1) * 16], tmp) 
            ctr = int.from_bytes(ctr, byteorder='big') + 1
            ctr = ctr.to_bytes(16, byteorder='big', signed=0)

    elif blkcipher == 1:
        cipher = DES.new(key, DES.MODE_ECB)
        nb_blocks = (int)(len(src_bytes) / 8)

        for i in range(nb_blocks+1):
            tmp = cipher.encrypt(ctr) 
            dst_bytes += xor(src_bytes[i * 8:(i + 1) * 8], tmp)
            ctr = int.from_bytes(ctr, byteorder='big') + 1
            ctr = ctr.to_bytes(16, byteorder='big', signed=0)

    return dst_bytes[:len(src_bytes)]


while True:
    BlkCip = int(input("블록암호를 선택하세요.  (AES = 0, DES = 1)  : "))
    if(BlkCip == 0 or BlkCip == 1):
        break
    else:
        print("다른 숫자를 입력하셨습니다.\n")

#BlkCip = 0 AES
#BlkCip = 1 DES

while True:
    mode = int(input("mode를 선택하세요.  (ECB = 0, CBC = 1, OFB = 2, CFB = 3, CTR = 4)  : "))
    if(mode>=0 and mode<=4):
        break
    else:
        print("다른 숫자를 입력하셨습니다.\n")

#mode = 0 ECB
#mode = 1 CBC
#mode = 2 OFB
#mode = 3 CFB pdf.57
#mode = 4 CTR

root = tkinter.Tk()
root.withdraw()

if(BlkCip == 0):
    print("\n --------------- AES가 선택되었습니다. ---------------")
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c") 
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f") #CBC, OFB, CFB
    ctr = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff") #CTR

    msg = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710") 
    print(" [ PlainText ] ")
    print (binascii.hexlify(msg))

    if(mode == 0):
        print(" [ AES - ECB 로 암호화된 CipherText ] ")
        dst = encrypt_ECB_bytes(0, key, iv, msg)
        print (binascii.hexlify(dst))
        dst2 = decrypt_ECB_bytes(0, key, iv, dst)
    elif(mode == 1):
        print(" [ AES - CBC 로 암호화된 CipherText ] ")
        dst = encrypt_CBC_bytes(0, key, iv, msg)
        print (binascii.hexlify(dst))
        dst2 = decrypt_CBC_bytes(0, key, iv, dst)
    elif(mode == 2):
        print(" [ AES - OFB 로 암호화된 CipherText ] ")
        dst = encrypt_OFB_bytes(0, key, iv, msg)
        print (binascii.hexlify(dst))
        dst2 = decrypt_OFB_bytes(0, key, iv, dst)
    elif(mode == 3):
        print(" [ AES - CFB 로 암호화된 CipherText ] ")
        dst = encrypt_CFB_bytes(0, key, iv, msg)
        print (binascii.hexlify(dst))
        dst2 = decrypt_CFB_bytes(0, key, iv, dst)
    elif(mode == 4):
        print(" [ AES - CTR 로 암호화된 CipherText ] ")
        dst = encrypt_CTR_bytes(0, key, ctr, msg)
        print (binascii.hexlify(dst))
        dst2 = decrypt_CTR_bytes(0, key, ctr, dst)

elif(BlkCip == 1):
    print("\n --------------- DES가 선택되었습니다. ---------------")
    key = bytes.fromhex("0123456789abcdef") 
    iv = bytes.fromhex("1234567890abcdef") #CBC, OFB, CFB
    ctr = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff") #CTR

    msg = bytes.fromhex("4e6f77206973207468652074696d6520666f7220616c6c20")
    print(" [ PlainText ] ")
    print (binascii.hexlify(msg))

    if(mode == 0):
        print(" [ DES - ECB 로 암호화된 CipherText ] ")
        dst = encrypt_ECB_bytes(1, key, iv, msg)
        print (binascii.hexlify(dst))
        dst2 = decrypt_ECB_bytes(1, key, iv, dst)
    elif(mode == 1):
        print(" [ DES - CBC 로 암호화된 CipherText ] ")
        dst = encrypt_CBC_bytes(1, key, iv, msg)
        print (binascii.hexlify(dst))
        dst2 = decrypt_CBC_bytes(1, key, iv, dst)
    elif(mode == 2):
        print(" [ DES - OFB 로 암호화된 CipherText ] ")
        dst = encrypt_OFB_bytes(1, key, iv, msg)
        print (binascii.hexlify(dst))
        dst2 = decrypt_OFB_bytes(1, key, iv, dst)
    elif(mode == 3):
        print(" [ DES - CFB 로 암호화된 CipherText ] ")
        dst = encrypt_CFB_bytes(1, key, iv, msg)
        print (binascii.hexlify(dst))
        dst2 = decrypt_CFB_bytes(1, key, iv, dst)
    elif(mode == 4):
        print(" [ DES - CTR 로 암호화된 CipherText ] ")
        dst = encrypt_CTR_bytes(1, key, ctr, msg)
        print (binascii.hexlify(dst))
        dst2 = decrypt_CTR_bytes(1, key, ctr, dst)

print(" [ 복호화된 PlainText ] ")
print (binascii.hexlify(dst2))

print()
print (" 복호화된 text가 평문과 일치 합니까? ", msg == dst2)
print()




'''
---------------------------------------------------------------------
    TEST VECTOR
---------------------------------------------------------------------

AES-128

<< ECB mode >>
Key 2b7e151628aed2a6abf7158809cf4f3c

Plaintext  6bc1bee22e409f96e93d7e117393172a 
Ciphertext 3ad77bb40d7a3660a89ecaf32466ef97 

Plaintext  ae2d8a571e03ac9c9eb76fac45af8e51 
Ciphertext f5d3d58503b9699de785895a96fdbaaf 

Plaintext  30c81c46a35ce411e5fbc1191a0a52ef 
Ciphertext 43b1cd7f598ece23881b00e3ed030688 

Plaintext  f69f2445df4f9b17ad2b417be66c3710 
Ciphertext 7b0c785e27e8ad3f8223207104725dd4 


<< CBC mode >>
Key 2b7e151628aed2a6abf7158809cf4f3c 
IV  000102030405060708090a0b0c0d0e0f 

Plaintext  6bc1bee22e409f96e93d7e117393172a 
Ciphertext 7649abac8119b246cee98e9b12e9197d 

Plaintext  ae2d8a571e03ac9c9eb76fac45af8e51
Ciphertext 5086cb9b507219ee95db113a917678b2

Plaintext  30c81c46a35ce411e5fbc1191a0a52ef
Ciphertext 73bed6b8e3c1743b7116e69e22229516

Plaintext  f69f2445df4f9b17ad2b417be66c3710 
Ciphertext 3ff1caa1681fac09120eca307586e1a7


<< CFB mode >>
Key 2b7e151628aed2a6abf7158809cf4f3c 
IV  000102030405060708090a0b0c0d0e0f 

Input Block 000102030405060708090a0b0c0d0e0f 
Output Block 50fe67cc996d32b6da0937e99bafec60
Plaintext  6bc1bee22e409f96e93d7e117393172a 
Ciphertext 3b3fd92eb72dad20333449f8e83cfb4a 

Input Block 3b3fd92eb72dad20333449f8e83cfb4a 
Output Block 668bcf60beb005a35354a201dab36bda 
Plaintext  ae2d8a571e03ac9c9eb76fac45af8e51 
Ciphertext c8a64537a0b3a93fcde3cdad9f1ce58b 

Plaintext  30c81c46a35ce411e5fbc1191a0a52ef 
Ciphertext 26751f67a3cbb140b1808cf187a4f4df 

Plaintext  f69f2445df4f9b17ad2b417be66c3710 
Ciphertext c04b05357c5d1c0eeac4c66f9ff7f2e6 


<< OFB mode >>
Key 2b7e151628aed2a6abf7158809cf4f3c 
IV  000102030405060708090a0b0c0d0e0f 

Plaintext  6bc1bee22e409f96e93d7e117393172a 
Ciphertext 3b3fd92eb72dad20333449f8e83cfb4a 

Plaintext  ae2d8a571e03ac9c9eb76fac45af8e51 
Ciphertext 7789508d16918f03f53c52dac54ed825 

Plaintext  30c81c46a35ce411e5fbc1191a0a52ef 
Ciphertext 9740051e9c5fecf64344f7a82260edcc 

Plaintext  f69f2445df4f9b17ad2b417be66c3710 
Ciphertext 304c6528f659c77866a510d9c1d6ae5e


<< CTR mode >>
Key          2b7e151628aed2a6abf7158809cf4f3c
Init.Counter f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff

Plaintext  6bc1bee22e409f96e93d7e117393172a
Ciphertext 874d6191b620e3261bef6864990db6ce

Plaintext  ae2d8a571e03ac9c9eb76fac45af8e51 
Ciphertext 9806f66b7970fdff8617187bb9fffdff 

Plaintext  30c81c46a35ce411e5fbc1191a0a52ef 
Ciphertext 5ae4df3edbd5d35e5b4f09020db03eab 

Plaintext  f69f2445df4f9b17ad2b417be66c3710 
Ciphertext 1e031dda2fbe03d1792170a0f3009cee

---------------------------------------------------------------------

DES

<< ECB mode >>
Key  0123456789abcdef

Plaintext  4e6f772069732074
Ciphertext 3fa40e8a984d4815
          
Plaintext  68652074696d6520
Ciphertext 6a271787ab8883f9
          
Plaintext  666f7220616c6c20
Ciphertext 893d51ec4b563b53


<< CBC mode >>
Key  0123456789abcdef
IV   1234567890abcdef

Plaintext  4e6f772069732074
Ciphertext e5c7cdde872bf27c
          
Plaintext  68652074696d6520
Ciphertext 43e934008c389c0f
          
Plaintext  666f7220616c6c20
Ciphertext 683788499a7c05f6


<< CFB mode >>
Key  0123456789abcdef
IV   1234567890abcdef

Plaintext  4e6f772069732074
Ciphertext f3096249c7f46e51
          
Plaintext  68652074696d6520
Ciphertext a69e839bla92f784
          
Plaintext  666f7220616c6c20
Ciphertext 03467133898ea622

<< OFB mode >>
Key  0123456789abcdef
IV   1234567890abcdef

Plaintext  4e6f772069732074
Ciphertext f3096249c7f46e51
          
Plaintext  68652074696d6520
Ciphertext 35f24a242eeb3d3f
          
Plaintext  666f7220616c6c20
Ciphertext 3d6d5be3255af8c3

<< CTR mode >>
Key            0123456789abcdef
Init.Counter   f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff

Plaintext  4e6f772069732074
Ciphertext 4b45aec2b39dcc09
          
Plaintext  68652074696d6520
Ciphertext 6d4ff996b383895d
          
Plaintext  666f7220616c6c20
Ciphertext 6345abc2bb82805d

'''
