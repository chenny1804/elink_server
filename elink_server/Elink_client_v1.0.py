#-*- coding:utf-8 -*-
import socket,sys
from time import sleep
from json import dumps,loads
import traceback
import struct,json
import base64
import binascii,math
from binascii import b2a_hex, a2b_hex
from Crypto.Cipher import AES
import threading,signal
import random,Queue
import logging

ADDR=('<broadcast>',26887)
BIND_STATUS="unbind"
AC_MAC="00:00:00:00:00:00"
AC_IP=""
DISCOVER_UNBIND_DATA={"type":"ap_discovery",
				"id":0001,
				"ap_mac":"08:60:6E:D4:58:1c",
				"ap_addr":"192.168.0.3",
				"ap_addr_bak":"169.254.12.36",
				"ac_mac":AC_MAC,
				"bind_st":BIND_STATUS,
				"have_param":0}
Aes_key="0000000000000000"
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
		# return b2a_hex(self.ciphertext)
		return self.ciphertext
	def decrypt(self, text):
		self.obj2 = AES.new(self.key, self.mode, self.iv)
		# print text
		plain_text  = self.obj2.decrypt(a2b_hex(text))
		# print "plain_text:->%r"%plain_text
		#return self.unpad(plain_text.rstrip('\0'))
		return plain_text.rstrip('\0')
def discover_send(ip):
	global BIND_STATUS
	global AC_MAC
	host=ip
	port=26886
	s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
	s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
	s.bind((host,port))
	while 1:
		sleep(5)
		print "send BIND_STATUS:",BIND_STATUS
		if BIND_STATUS == "unbind":
			logging.debug("send unbind discovery")
			s.sendto(dumps(DISCOVER_UNBIND_DATA),ADDR)
			continue
		DISCOVER_UNBIND_DATA["bind_st"]=BIND_STATUS
		DISCOVER_UNBIND_DATA["ac_mac"]=AC_MAC
		# print DISCOVER_UNBIND_DATA
		print "send bind discovery"
		s.sendto(dumps(DISCOVER_UNBIND_DATA),ADDR)
def discover_listen(ip):
	host=ip
	port=26887
	global BIND_STATUS
	global AC_MAC
	global AC_IP
	s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
	s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
	s.bind((host,port))
	while 1:
		try:
		  data,addr=s.recvfrom(2048)
		  print "got data from",addr
		  datas=loads(data)
		  # print datas
		  if datas["type"] == "bind":
		  		print "--->>>>recv AC bind---->>>>>"
		  		BIND_STATUS="bind"
		  		AC_MAC=datas["ac_mac"]
		  		AC_IP=datas["ac_addr"]
		  		print "listen BIND_STATUS:->>",BIND_STATUS
		  sleep(5)
		except KeyboardInterrupt:
		  raise
class tcp_client(threading.Thread):
	def __init__(self,client_addr,server_addr):
		self.server_addr=server_addr
		self.client_addr=client_addr
		self.Aes_flags=False
		self.crypt_class=None
		self.recv_queue=Queue.Queue()
		self.send_queue=Queue.Queue()
		self.tcp_client=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.keepalive_status=False
		self.ack_sequence=0
		threading.Thread.__init__(self)
	def _build_socket(self):
		self.tcp_client.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
		try:
			self.tcp_client.bind(self.client_addr)
			self.tcp_client.connect(self.server_addr)
		except socket.error:
			print "fail to setup socket connection"
	def _socket_recv(self):
		while True:
			recv_data=self.tcp_client.recv(2048)
			if len(recv_data) == 0:
				print "response error"
				self.tcp_client.close()
			self.recv_queue.put(recv_data)
	def _socket_send(self):
		while True:
			if self.send_queue.empty():
				continue
			self.tcp_client.sendall(self.send_queue.get())
	def _keep_alive(self):
		while  True:
			if self.keepalive_status:
				self.send_queue.put(self._pack_data(self.crypt_class.encrypt(self._keepalive_data(self.ack_sequence))))
			sleep(5)
			continue
	def _analysis_socket(self):
		while True:
			if self.recv_queue.empty():
				continue
			recv_data=self.recv_queue.get()
			if len(recv_data) > 8:
				Flag,Len=struct.unpack("!4sI",recv_data[0:8])
				print "FLag:%s,Len:%d"%(Flag,Len)
				if self.Aes_flags == False :
					recv_data_json=loads(recv_data[8:])
					#print "recv_data_json:",recv_data_json
					if recv_data_json["type"] == "keyngack":
						send_data=self._dh_data(recv_data_json["sequence"])
						print send_data
						self.send_queue.put(self._pack_data(dumps(send_data))) 
					elif recv_data_json["type"] == "dh":
						print recv_data_json["data"].keys()
						dh_key=int(binascii.hexlify(base64.b64decode(recv_data_json["data"]["dh_key"])), base=16)
						dh_p=int(binascii.hexlify(base64.b64decode(recv_data_json["data"]["dh_p"])), base=16)
						dh_g=int(binascii.hexlify(base64.b64decode(recv_data_json["data"]["dh_g"])), base=16)
						print "dh_key->:",dh_key
						print "dh_p->:",dh_p
						print "dh_g->:",dh_g
						self.Aes_key=self._get_aes(dh_key,dh_p)
						print "aes->:",self.Aes_key
						self.crypt_class=crypt(self.Aes_key)
						encrypt_data=self.crypt_class.encrypt(self._reg(recv_data_json["sequence"]))
						# print reg(recv_data_json["sequence"])
						# print crypt_class.decrypt(b2a_hex(encrypt_data))
						self.send_queue.put(self._pack_data(self.crypt_class.encrypt(self._reg(recv_data_json["sequence"])))) 
						self.Aes_flags=True
				else:
					logging.debug("Aes_flags:->%r"%self.Aes_flags) 
					datas=struct.unpack("!"+str(len(recv_data[8:]))+"s",recv_data[8:])
					# print "cryp data:->",datas
					logging.debug("Aes_key:::::->%r"%self.Aes_key) 
					decode_recv_data=loads(self.crypt_class.decrypt(b2a_hex(datas[0])))
					print "decryp data:->",decode_recv_data
					logging.debug("decode_recv_data->%r"%decode_recv_data)
					if decode_recv_data["type"] == "cfg":
						self.send_queue.put(self._pack_data(self.crypt_class.encrypt(self._ack_data(decode_recv_data["sequence"]))))
						# print "---send cfg ack  data----"
					elif decode_recv_data["type"] == "ack":
						self.keepalive_status=True
						self.ack_sequence=decode_recv_data["sequence"] 
	def _pack_data(self,data):	
		logging.debug("data-len:%d"%len(data))
		data=struct.pack("!II"+str(len(data))+"s",0x3f721fb5,len(data),data)
		return data
	def run(self):
		self._build_socket()

		send_thread=threading.Thread(target=self._socket_send,name="send thread",args=())
		recv_thread=threading.Thread(target=self._socket_recv,name="recv thread",args=())
		analysis_thread=threading.Thread(target=self._analysis_socket,name="analysis thread",args=())
		cmd_thread=threading.Thread(target=self._sendConfig,name="send command",args=())
		keepalive_thread=threading.Thread(target=self._keep_alive,name="keepalive thread",args=())


		send_thread.setDaemon(True)
		recv_thread.setDaemon(True)
		analysis_thread.setDaemon(True)
		cmd_thread.setDaemon(True)
		keepalive_thread.setDaemon(True)

		send_thread.start()
		recv_thread.start()
		analysis_thread.start()
		cmd_thread.start()
		keepalive_thread.start()

		self.send_queue.put(self._pack_data(self._keyn_req_data()))
	def _keyn_req_data(self):
		data={"type":"keyngreq","sequence":1,
			"mac":"08:60:6e:d4:58:1c","version":"V2016.1.0",
			"keymodelist":[{"keymode":"dh"}]}
		return dumps(data)	
	def _keepalive_data(self,sequence):
		data={"type":"keepalive","sequence":int(sequence)+1,"mac":"08:60:6e:d4:58:1c","connected_time":"65535","signal_level":"3"}
		# data={"type":"keepalive","sequence":int(sequence)+1,"mac":"08:60:6e:d4:58:1c"}
		logging.info("keepalive data->%r"%data)
		return dumps(data)	
	def _ack_data(self,sequence):
		data={"type":"ack","sequence":int(sequence),"mac":"08:60:6e:d4:58:1c"}
		# data={"type":"ack","sequence":int(sequence)}
		return dumps(data)
	def _reg(self,sequence):
		data={"type":"dev_reg","sequence":int(sequence)+1,
			"mac":"08:60:6e:d4:58:1c",
			"data":{"vendor":"netcore","model":"NAP871","url":"192.168.100.1","wireless":"yes"}}
		# data={"type":"dev_reg","mac":"08:60:6e:d4:58:1c"}
		return dumps(data)
	def _get_aes(self,dh_key,dh_p):
		prime="P4T2O6UlQe+bWTImuMKHNQ=="
		prime=int(binascii.hexlify(base64.b64decode(prime)), base=16)
		aes_key=pow(dh_key,prime,dh_p)
		logging.debug("Aes key->"+str(aes_key)) 
		return str(hex(aes_key))[2:-1]
	def _dh_data(self,sequence):
		prime="P4T2O6UlQe+bWTImuMKHNQ=="
		prime=int(binascii.hexlify(base64.b64decode(prime)), base=16)
		dh_g=2
		dh_p=199521395092713581615548352749246148387
		dh_new_key=pow(dh_g,prime,dh_p)
		dh_new_key_base64=base64.b64encode(binascii.unhexlify(str(hex(dh_new_key))[2:-1]))
		dh_p_base64=base64.b64encode(binascii.unhexlify(str(hex(dh_p))[2:-1]))
		data={"type":"dh","sequence":int(sequence)+1,
			"mac":"08:60:6e:d4:58:1c",
			"data":{"dh_key":dh_new_key_base64,"dh_p":dh_p_base64,"dh_g":"Ag=="}}
		return data
	def _sendConfig(self):
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
					print "Checking your String,Not Json Format"
					continue
				try:
					self.send_queue.put(self._pack_data(self.crypt_class.encrypt(json_str_config)))
				except Exception as e:
					logging.error("Error bad File")
					sys.exit(0)
			else:
				continue
def log(name,level):
	logging.basicConfig(level=logging.DEBUG,
                format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                datefmt='%a, %d %b %Y %H:%M:%S',
                filename=name,
                filemode='w')
	console = logging.StreamHandler()
	console.setLevel(level)
	formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
	console.setFormatter(formatter)
	logging.getLogger('').addHandler(console)
def quit(signum,frame):
	print "Ctr+C Stoping..."
	sys.exit()
if __name__ == '__main__':
	#discover_server()
	#tcp_client("192.168.0.1",20000)
	log("elink.log",logging.INFO)
	try:
		signal.signal(signal.SIGINT, quit)
		signal.signal(signal.SIGTERM, quit)

		t1=threading.Thread(target=discover_send,name="discovery send thread",args=("192.168.0.3",))
		t2=threading.Thread(target=discover_listen,name="discovery listen thread",args=("192.168.0.3",))
		t1.setDaemon(True)
		t2.setDaemon(True)
		t1.start()
		t2.start()
		while 1:
			if AC_IP != "":
				print "get ac_ip ac_ip",AC_IP
				break
		t3=tcp_client(("192.168.0.3",random.randint(10000,65535)),(AC_IP,20000))
		t3.start()
		while True:
			pass
	except Exception,exc:
		print exc