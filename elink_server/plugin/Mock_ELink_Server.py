#-*- coding:utf-8 -*-

from SocketServer import TCPServer, BaseRequestHandler,ThreadingTCPServer
import traceback
import struct,json
import base64
import binascii,math,sys
from binascii import b2a_hex, a2b_hex
try:
	from Crypto.Cipher import AES
except ImportError:
	print "Don't import AES from Crypto.Cipher"
import logging
import threading
from random import randint
KEYNGREQ=True
DH=True
DEV_REG=True
KEEPALIVE=True
COUNT=999999999
REQUEST={}
class crypt():
	def __init__(self,key):
		self.key=binascii.a2b_hex(key)
		self.iv  = a2b_hex('00000000000000000000000000000000')
		self.mode = AES.MODE_CBC
		self.PAD_CH='\0'
		self.BS = AES.block_size
		self.pad = lambda s: s + (self.BS - len(s) % self.BS) * self.PAD_CH
		self.unpad = lambda s : s[0:-ord(s[-1])]
	def encrypt(self, text):
		text = self.pad(text)
		self.obj1 = AES.new(self.key, self.mode, self.iv)
		self.ciphertext = self.obj1.encrypt(text)
		return b2a_hex(self.ciphertext)
	def decrypt(self, text):
		self.obj2 = AES.new(self.key, self.mode, self.iv)
		plain_text  = self.obj2.decrypt(a2b_hex(text))
		#print "plain_text:->%r"%plain_text
		#return self.unpad(plain_text.rstrip('\0'))
		return plain_text.rstrip('\0')
class MyBaseRequestHandlerr(BaseRequestHandler):
    """
    #从BaseRequestHandler继承，并重写handle方法
    """
    def handle(self):
        #循环监听（读取）来自客户端的数据
		self.AES_FLAG=False
		self.Aes_key="00000000000000000000000000000000"
		self.dh_key=""
		self.times=COUNT
		self.conn=self.request
		self.p=crypt(self.Aes_key)
		print "ELINK SERVER RUNNING....."
		Inputthread=threading.Thread(target=self.sendConfig)
		Inputthread.start()
		while True:
            #当客户端主动断开连接时，self.recv(1024)会抛出异常
			try:
				#一次读取1024字节
				data = self.request.recv(1024)
				#print "\ndata length:"+str(len(data))
				if len(data) == 0:
					logging.info("Connent Scaning!!!!")
					break
				if len(data) > 8:
					json_str=self.unpack(data)
					if json_str == 0:
						continue
						self.AES_FLAG=False
					logging.debug("receive from (%s,%s)" % (self.client_address))
					logging.debug("RECEIVE JSON:<----:",json_str)
					if json_str["type"] == "keyngreq" and KEYNGREQ:
						#收到KEYNGRE报文，回应KEYNGREQ
						self.send_keyngack(json_str)
					elif json_str["type"] == "dh" and DH:
						#收到DH报文，回应ACK
						self.send_dh_ack(json_str)
					elif (json_str["type"] == "dev_reg" and DEV_REG ) \
					 or (json_str["type"] == "keepalive" and KEEPALIVE):	
					 	# 收到dev_reg或者keepalive，回复ack
					 	#if里面的代码使用来测试上回复上一阶段报文
					 	# if self.times <=0:
					 	# 	datas={"type":"dh",
					 	# 	"mac":json_str["mac"],
					 	# 	"sequence":json_str["sequence"],
					 	# 	"data":{"dh_key":self.dh_key}}
							# encrypt_data=self.p.encrypt(json.dumps(datas,sort_keys=True))
							# self.sendall(a2b_hex(encrypt_data))
							# continue
						REQUEST[self.client_address[0]]=[self.request,self.client_address[1],self.Aes_key]
						self.send_ack(json_str)
						logging.debug("Set CNN :(%s,%s)"%(self.client_address))
						self.times=self.times-1
						logging.debug("TIMES->:%s"%str(self.times))
					else:
						logging.info("\n\tfrom (%s,%s)\nreviced cfg ACK->:\n\t%s"%(self.client_address[0],
							str(self.client_address[1]),
							json.dumps(json_str)))
						continue
			except:
				print "AES_FLAG:%r"%self.AES_FLAG
				print "Recieve Data:%r"%data
				self.request.close()
				traceback.print_exc()
				#Inputthread.start()
				break
    def send(self,data):
        self.request.sendall(data)
    def pack(self,data):
        #print "raw->",data
        data=struct.pack("!II"+str(len(data))+"s",0x3f721fb5,len(data),data)
        return data
    def unpack(self,data):
    	Flag,Len=struct.unpack("!4sI",data[0:8])
    	logging.debug("Len:%d"%Len)
    	logging.debug("Data real Length:%d"%len(data[8:]))
    	if Len !=  len(data[8:]):
    		logging.error("ERROR of  Len is not equare  data")
    	datas=struct.unpack("!"+str(Len)+"s",data[8:])
    	if self.AES_FLAG and Flag == a2b_hex('3f721fb5'):
    		logging.debug("AES decrypt data")
    		#print REQUEST
    		self.p=crypt(self.Aes_key)
    		decrypdatas=self.p.decrypt(b2a_hex(datas[0]))
    		#decrypdatas=P.decrypt(b2a_hex(datas[0]))
    		return json.loads(decrypdatas)
    	elif Flag==a2b_hex('3f721fb5'):
    		#print datas[0]
    		return json.loads(datas[0])
    	else:
    		return 0
    def send_keyngack(self,json_str):
		datas={"type":"keyngack",
				"sequence":json_str["sequence"],
				"mac":"00112233ABCD",
				"keymode":"dh"}
		self.sendall(json.dumps(datas,sort_keys=True))
		self.AES_FLAG=False
		logging.debug("\nKEYNGREQY ACK SEND>>>>\n---->:%r"%datas)
    def send_dh_ack(self,json_str):
	#收到DH报文，回应ACK
		dh_Server_key,self.Aes_key=self.DH_Exchange(json_str["data"]["dh_key"],
		json_str["data"]["dh_p"],json_str["data"]["dh_g"])
		logging.info("\n\t\tdh_Server_key:"+str(dh_Server_key))
		logging.info("\n\t\tAES share KEY:"+self.Aes_key)
		self.dh_key=dh_Server_key
		self.p=crypt(self.Aes_key)
		datas={"type":"dh",
				"mac":json_str["mac"],
				"sequence":json_str["sequence"],
				"data":{"dh_key":self.dh_key}}
		self.sendall(json.dumps(datas,sort_keys=True))
		self.AES_FLAG=True
		logging.debug("\nDH ACK SEND>>>>\n---->:%r"%datas)
    def send_ack(self,json_str):
 	#收到dev_reg或者keepalive，回复ack
		datas={"type":"ack",
			"sequence":json_str["sequence"],
			"mac":json_str["mac"]
				}
		self.p=crypt(self.Aes_key)
		encrypt_data=self.p.encrypt(json.dumps(datas,sort_keys=True))
		#encrypt_data=P.encrypt(json.dumps(datas,sort_keys=True))
		self.sendall(a2b_hex(encrypt_data))
		logging.debug(json_str["type"].upper()+" ACK SEND>>>>\n---->:%r\n"%datas)
		self.AES_FLAG=True   	
    def sendall(self,data):
    	self.send(self.pack(data))
    def sendConfig(self):
    	while True:
			input_config=raw_input("Input Json#")
			if len(input_config) > 1:
				try:
					json_str_config=json.dumps(eval(input_config))
					#print dir(self.conn)
					#print "Client address:(%r,%r)" %(self.client_address)
					self.AES_FLAG=True 
				except Exception as e:
					logging.error("\nERROR",e)
					logging.error("\nChecking your String,Not Json Format")
					continue
				try:
					for i in REQUEST:
						P=crypt(REQUEST[i][2])
						encrypt_config=P.encrypt(json_str_config)
						data_config=self.pack(a2b_hex(encrypt_config))
						logging.info("\n\tsend to %s,%s"%(i,REQUEST[i][1]))
						REQUEST[i][0].sendall(data_config)
						#self.request.sendall(data_config)
				except Exception as e:
					logging.error("Error bad File")
					sys.exit(0)
			else:
				continue
    def DH_Exchange(self,dh_key,dh_p,dh_g):
    	#print "\t\tdh_key:",dh_key,'\n\t\tdh_p:',dh_p,'\n\t\t',dh_g
    	dh_key=int(binascii.hexlify(base64.b64decode(dh_key)),base=16)
    	dh_p=int(binascii.hexlify(base64.b64decode(dh_p)),base=16)
    	dh_g=int(binascii.hexlify(base64.b64decode(dh_g)),base=16)
    	logging.info("dh_key->%s"%dh_key)
    	logging.info("dh_p->%s"%dh_p)
    	logging.info("dh_p->%s"%dh_g)
    	prime_list=["cL5BL2JtUNzjdGXYQe9kmw==",
    	"dwqf1gFbd6/V3tEBHnQemA==",
    	"P4T2O6UlQe+bWTImuMKHNQ==",
    	"RB3adPPfFhzqSXVMTCLtbQ==",
    	"cL5BL2JtUNzjdGXYQe9kmw=="]
    	prime=int(binascii.hexlify(base64.b64decode(prime_list[randint(0,4)])), base=16)
    	dh_new_key=pow(dh_g,prime,dh_p)
    	aes_key=pow(dh_key,prime,dh_p)
    	aes_key_str=str(hex(aes_key))[2:-1]
    	if len(aes_key_str) < 32:
    		aes_key_str=aes_key_str+(32-len(aes_key_str))*'0'
    	return base64.b64encode(binascii.unhexlify(str(hex(dh_new_key))[2:-1])),str(hex(aes_key))[2:-1]
if __name__ == "__main__":
	logging.basicConfig(level=logging.DEBUG,
                format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                datefmt='%a, %d %b %Y %H:%M:%S',
                filename='ELINK.log',
                filemode='w')
	console = logging.StreamHandler()
	console.setLevel(logging.INFO)
	formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
	console.setFormatter(formatter)
	logging.getLogger('').addHandler(console)
	host = "192.168.1.100"       #主机名，可以是ip,像localhost的主机名,或""
	port = 32768     #端口
	addr = (host, port)
 
    #购置TCPServer对象，
	#server = TCPServer(addr, MyBaseRequestHandlerr)
	server=ThreadingTCPServer(addr, MyBaseRequestHandlerr)
	#启动服务监听
	server.serve_forever()
	