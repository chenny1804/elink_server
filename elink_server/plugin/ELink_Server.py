#-*- coding:utf-8 -*-

from SocketServer import TCPServer, BaseRequestHandler
import traceback
import struct,json
import base64
import binascii,math
from binascii import b2a_hex, a2b_hex
from Crypto.Cipher import AES
KEYNGREQ=True
DH=True
KEEPALIVE=False
class crypt():
	def __init__(self,key):
		self.key=binascii.a2b_hex(key)
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
		plain_text  = self.obj2.decrypt(a2b_hex(text))
		#return self.unpad(plain_text.rstrip('\0'))
		return plain_text.rstrip('\0')
class MyBaseRequestHandlerr(BaseRequestHandler):
    """
    #从BaseRequestHandler继承，并重写handle方法
    """
    def handle(self):
        #循环监听（读取）来自客户端的数据
		self.AES_FLAG=False
		self.Aes_key="0000000000000000"
		while True:
            #当客户端主动断开连接时，self.recv(1024)会抛出异常
			try:
				#一次读取1024字节,并去除两端的空白字符(包括空格,TAB,\r,\n)
				data = self.request.recv(4096).strip()
				print "data length:",len(data)
				if len(data) == 0:
					self.step=0
					print "Connent Scaning!!!!"
					self.request.close()
				if len(data) > 8:
					Flag,Len=struct.unpack("!4sI",data[0:8])
					print "FLag:%s,Len:%d"%(Flag,Len)
					#self.client_address是客户端的连接(host, port)的元组
					print "receive from (%r):%r" % (self.client_address, data)
					datas=struct.unpack("!"+str(Len)+"s",data[8:])
					if self.AES_FLAG:
						datas=struct.unpack("!"+str(len(data[8:]))+"s",data[8:])
						print "cryp data:->",datas
						print "Aes_key:->",self.Aes_key
						p=crypt(self.Aes_key)
						print "decryp data:->",p.decrypt(b2a_hex(datas[0]))
						#json_str=json.loads(datas[0])
						datas={"type":"ack",
						"sequence":1,
						"mac":"081079A6C4E0"
						}
						print "AES_encrypt_data:",p.encrypt(json.dumps(datas,sort_keys=True))
						data=self.pack(p.encrypt(json.dumps(datas,sort_keys=True)))
						self.send(data)
					else:
						json_str=json.loads(datas[0])
						print "json_str:",json_str
						print json_str["type"]
					if json_str["type"] == "keyngreq" and KEYNGREQ:
						datas={"type":"keyngack",
							"sequence":json_str["sequence"],
							"mac":"00112233ABCD",
							"keymode":"dh"}
						data=self.pack(json.dumps(datas,sort_keys=True))
						#print "pack data->",data
						self.send(data)
						self.AES_FLAG=False
						print "send keyngack"
					elif json_str["type"] == "dh" and DH:
						dh_key=base64.b64decode(json_str["data"]["dh_key"])
						dh_p=base64.b64decode(json_str["data"]["dh_p"])
						dh_g=base64.b64decode(json_str["data"]["dh_g"])
						dh_key_int=int(binascii.hexlify(dh_key), base=16)
						dh_p_int=int(binascii.hexlify(dh_p), base=16)
						dh_g_int=int(binascii.hexlify(dh_g), base=16)
						dh_Server_key,self.Aes_key=self.DH_Exchange(dh_key_int,dh_p_int,dh_g_int)
						print "\t\t\t\t\tdh_key:%r"%dh_key,"->",str(dh_key_int)
						print "\t\t\t\t\tdh_p:%r"%dh_p,"->",str(dh_p_int)
						print "\t\t\t\t\tdh_g:%r"%dh_g,"->",str(dh_g_int)
						print "\t\t\t\t\tdh_Server_key",str(dh_Server_key)
						print "\t\t\t\tAES share KEY",self.Aes_key
						#self.aes_crypto=prpcrypt(Aes_key)
						datas={"type":"dh",
						"mac":json_str["mac"],
						"sequence":json_str["sequence"],
						"data":{"dh_key":dh_Server_key}}
						data=self.pack(json.dumps(datas,sort_keys=True))
                        #print "pack data->",data
						self.send(data)
						self.AES_FLAG=True
						print "send dh"
					elif json_str["type"] == "keepalive" and KEEPALIVE:
						print "------KEEP ALIVE-----"
						datas={"type":"ack",
							"sequence":json_str["sequence"],
							"mac":json_str["mac"]
							}
						data=self.pack(json.dumps(datas,sort_keys=True))
						#print "pack data->",data
						self.send(data)
						self.AES_FLAG=True
						print "Response KEEPALIVE"
                #转换成大写后写回(发生到)客户端
                #self.request.sendall(data.upper())
			except:
				self.request.close()
				traceback.print_exc()
				break
    def send(self,data):
        self.request.sendall(data)
    def pack(self,data):
        #print "raw->",data
        data=struct.pack("!II"+str(len(data))+"s",0x3f721fb5,len(data),data)
        return data
	def convert(self,key):
		return int(binascii.hexlify(key), base=16)
    def DH_Exchange(self,dh_key,dh_p,dh_g):
		prime_list=["cL5BL2JtUNzjdGXYQe9kmw==",
		"dwqf1gFbd6/V3tEBHnQemA==",
		"P4T2O6UlQe+bWTImuMKHNQ==",
		"RB3adPPfFhzqSXVMTCLtbQ==",
		"cL5BL2JtUNzjdGXYQe9kmw=="]
		prime=int(binascii.hexlify(base64.b64decode(prime_list[0])), base=16)
		dh_new_key=pow(dh_g,prime,dh_p)
		aes_key=pow(dh_key,prime,dh_p)
		return base64.b64encode(binascii.unhexlify(str(hex(dh_new_key))[2:-1])),str(hex(aes_key))[2:-1]
if __name__ == "__main__":
 #telnet 127.0.0.1 9999
	host = "192.168.0.2"       #主机名，可以是ip,像localhost的主机名,或""
	port = 20000     #端口
	addr = (host, port)
 
    #购置TCPServer对象，
	server = TCPServer(addr, MyBaseRequestHandlerr)
    #启动服务监听
	server.serve_forever()