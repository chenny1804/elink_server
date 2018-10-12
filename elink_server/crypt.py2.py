#!/usr/bin/env python
# -*- coding: utf-8 -*-

from Crypto.Cipher import AES
import base64
import os,binascii

BLOCK_SIZE = 16
PADDING = '\0'
pad_it = lambda s: s+(16 - len(s)%16)*PADDING  
key = binascii.a2b_hex("69dc1d19c0829536a8bb7305a7f303c0")
iv = '0000000000000000'

#使用aes算法，进行加密解密操作
#为跟java实现同样的编码，注意PADDING符号自定义
def encrypt_aes(sourceStr):
    generator = AES.new(key, AES.MODE_CBC, iv)
    crypt = generator.encrypt(pad_it(sourceStr))
    cryptedStr = base64.b64encode(crypt)
    return cryptedStr

def decrypt_aes(cryptedStr):
    generator = AES.new(key, AES.MODE_CBC, iv)
    #cryptedStr = base64.b64decode(cryptedStr)
    recovery = generator.decrypt(cryptedStr)
    decryptedStr = recovery.rstrip(PADDING)
    return decryptedStr

sourceStr = 'password^*(&( 09-8ADF'

#f='567fd97377dc9d9f54760f37bd3f1fd8ca395c7dc638d1b4effed3d1ff9730ebf4db166260331174318e75600dbef68e5b8a89a02d31bb84d23d1bf7705af69fc4f64755448636097aa6af76f49dcc93c15f0433ae6aebdd1243aa7e35b4bb08431396d643c0cb489ab3136abff605f19dbf1e1cd0e73a99a0bdd8816ba31559f4a6e9e20617906cec83450337aebe9c16798f0ef145418471f9c340a6c729d875e6dfcd69a2b8a3e0bd9d2c1a9a82be50ce7dc19c56dfa018953ac32b2ed2c6'

f='5ae3850ae0fbd825fd02f5d995841c6b5d5c4d48f081055626b1eb61843952dcd3423e5f4ff9f9edb3402d430436f617c69f6349ea7901ce1a7b537a472d1f7e'
#print encrypt_aes(sourceStr)
print decrypt_aes(binascii.a2b_hex(f))