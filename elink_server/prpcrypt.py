#!/usr/bin/env python
# -*- coding:utf-8 -*- 
#@author: rui.xu
#这里使用pycrypto‎库
#按照方法:easy_install pycrypto‎
 
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
 
class prpcrypt():
    def __init__(self,key):
        self.key = a2b_hex(key)
        self.mode = AES.MODE_CBC
     
    #加密函数，如果text不足16位就用空格补足为16位，
    #如果大于16当时不是16的倍数，那就补足为16的倍数。
    def encrypt(self,text):
        cryptor = AES.new(self.key,self.mode,b'0000000000000000')
        #这里密钥key 长度必须为16（AES-128）,
        #24（AES-192）,或者32 （AES-256）Bytes 长度
        #目前AES-128 足够目前使用
        length = 16
        count = len(text)
        if count < length:
            add = (length-count)
            #\0 backspace
            text = text + ('\0' * add)
        elif count > length:
            add = (length-(count % length))
            text = text + ('\0' * add)
        self.ciphertext = cryptor.encrypt(text)
        #因为AES加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题
        #所以这里统一把加密后的字符串转化为16进制字符串
        return b2a_hex(self.ciphertext)
     
    #解密后，去掉补足的空格用strip() 去掉
    def decrypt(self,text):
		cryptor = AES.new(self.key,self.mode,'0000000000000000')
		plain_text  = cryptor.decrypt(a2b_hex(text))
		for i in range(0,len(plain_text)):
			print plain_text[i]
		return plain_text.rstrip('\0')
 
if __name__ == '__main__':
	pc = prpcrypt("a76966f5c040c99078591b75450cd1df") #初始化密钥
	f='567fd97377dc9d9f54760f37bd3f1fd8ca395c7dc638d1b4effed3d1ff9730ebf4db166260331174318e75600dbef68e5b8a89a02d31bb84d23d1bf7705af69fc4f64755448636097aa6af76f49dcc93c15f0433ae6aebdd1243aa7e35b4bb08431396d643c0cb489ab3136abff605f19dbf1e1cd0e73a99a0bdd8816ba31559f4a6e9e20617906cec83450337aebe9c16798f0ef145418471f9c340a6c729d875e6dfcd69a2b8a3e0bd9d2c1a9a82be50ce7dc19c56dfa018953ac32b2ed2c6'
	d = pc.decrypt(f) #解密
	print "解密:",d