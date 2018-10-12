from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex,hexlify,unhexlify
import base64 
import struct,json
class crypt():
	def __init__(self,key):
		self.key=unhexlify(key)
		self.iv  = '0000000000000000'
		self.mode = AES.MODE_CBC
		self.BS = AES.block_size
		self.pad = lambda s: s + (self.BS - len(s) % self.BS) * chr(self.BS - len(s) % self.BS)
		self.unpad = lambda s : s[0:-ord(s[-1])]
	def encrypt(self, text):
		text = self.pad(text)
		self.obj1 = AES.new(self.key, self.mode, self.iv)
		self.ciphertext = self.obj1.encrypt(text)
		return b2a_hex(self.ciphertext)
	def decrypt(self, text):
		self.obj2 = AES.new(self.key, self.mode, self.iv)
		plain_text  = self.obj2.decrypt(unhexlify(text))
		#print plain_text
		#print plain_text.rstrip('\0')
		return plain_text.rstrip('\0')
		#return self.unpad(plain_text.rstrip('\0'))

if __name__ == '__main__':
	pc = crypt("a76966f5c040c99078591b75450cd1df")
	#pc.key=0xa76966f5c040c99078591b75450cd1df
	e = pc.encrypt('{"type": "dev_reg","sequence":5171,"mac": "081079A6C4E0","data": {"vendor":"Netcore","model":"NAP850+","url": "","wireless": "no"},"phonemac":"000000000000"}')
	print type(e),e
	d = pc.decrypt(e)
	print d
	#f='567fd97377dc9d9f54760f37bd3f1fd8ca395c7dc638d1b4effed3d1ff9730ebf4db166260331174318e75600dbef68e5b8a89a02d31bb84d23d1bf7705af69fc4f64755448636097aa6af76f49dcc93c15f0433ae6aebdd1243aa7e35b4bb08431396d643c0cb489ab3136abff605f19dbf1e1cd0e73a99a0bdd8816ba31559f4a6e9e20617906cec83450337aebe9c16798f0ef145418471f9c340a6c729d875e6dfcd69a2b8a3e0bd9d2c1a9a82be50ce7dc19c56dfa018953ac32b2ed2c6'
	#print pc.decrypt(f)
	
	#pc1=crypt("69dc1d19c0829536a8bb7305a7f303c0")
	#e="5ae3850ae0fbd825fd02f5d995841c6b5d5c4d48f081055626b1eb61843952dcd3423e5f4ff9f9edb3402d430436f617c69f6349ea7901ce1a7b537a472d1f7e"
	#print pc1.decrypt(e)