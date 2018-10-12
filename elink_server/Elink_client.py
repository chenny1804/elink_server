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
import random
ADDR=('<broadcast>',26887)
BIND_STATUS="unbind"
AC_MAC="00:00:00:00:00:00"
AC_IP=""
DISCOVER_UNBIND_DATA={"type":"ap_discovery",
				"id":0001,
				"ap_mac":"08:60:6E:D4:58:1c",
				"ap_addr":"192.168.0.2",
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
def discover_send():
	global BIND_STATUS
	global AC_MAC
	host="192.168.0.2"
	port=26886
	s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
	s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
	s.bind((host,port))
	while 1:
		sleep(5)
		print "send BIND_STATUS:",BIND_STATUS
		if BIND_STATUS == "unbind":
			print "send unbind discovery"
			s.sendto(dumps(DISCOVER_UNBIND_DATA),ADDR)
			continue
		DISCOVER_UNBIND_DATA["bind_st"]=BIND_STATUS
		DISCOVER_UNBIND_DATA["ac_mac"]=AC_MAC
		print DISCOVER_UNBIND_DATA
		print "send bind discovery"
		s.sendto(dumps(DISCOVER_UNBIND_DATA),ADDR)
def discover_listen():
	host='192.168.0.2'
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
		  print datas
		  if datas["type"] == "bind":
		  		print "--->>>>recv AC bind---->>>>>"
		  		BIND_STATUS="bind"
		  		AC_MAC=datas["ac_mac"]
		  		AC_IP=datas["ac_addr"]
		  		print "listen BIND_STATUS:->>",BIND_STATUS
		  sleep(5)
		except KeyboardInterrupt:
		  raise
def tcp_client(ip,port):
	server_ip=ip
	server_port=port
	tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	tcp_client.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
	Aes_flags=False
	crypt_class=None
	
	try:
		tcp_client.bind(("192.168.0.2",random.randint(10000,65535)))
		tcp_client.connect((server_ip, server_port))
	except socket.error:
		print "fail to setup socket connection"
	else:
		data={"type":"keyngreq","sequence":1,
		"mac":"08:60:6e:d4:58:1c","version":"V2016.1.0",
		"keymodelist":[{"keymode":"dh"}]}
		send_data=pack_data(dumps(data))
		tcp_client.sendall(send_data)
	while 1:
		# recv_data=tcp_client.recv(2048).strip()
		recv_data=tcp_client.recv(2048)
		if len(recv_data) == 0:
			print "response error"
			tcp_client.close()
		elif len(recv_data) > 8:
			Flag,Len=struct.unpack("!4sI",recv_data[0:8])
			print "FLag:%s,Len:%d"%(Flag,Len)
			# print recv_data[8:]
			#datas=struct.unpack("!"+str(Len)+"s",recv_data[8:])
			if Aes_flags == False :
				recv_data_json=loads(recv_data[8:])
				#print "recv_data_json:",recv_data_json
				if recv_data_json["type"] == "keyngack":
					send_data=dh_data(recv_data_json["sequence"])
					print send_data
					tcp_client.sendall(pack_data(dumps(send_data)))
				elif recv_data_json["type"] == "dh":
					print recv_data_json["data"].keys()
					dh_key=int(binascii.hexlify(base64.b64decode(recv_data_json["data"]["dh_key"])), base=16)
					dh_p=int(binascii.hexlify(base64.b64decode(recv_data_json["data"]["dh_p"])), base=16)
					dh_g=int(binascii.hexlify(base64.b64decode(recv_data_json["data"]["dh_g"])), base=16)
					print "dh_key->:",dh_key
					print "dh_p->:",dh_p
					print "dh_g->:",dh_g
					Aes_key=get_aes(dh_key,dh_p)
					print "aes->:",Aes_key
					crypt_class=crypt(Aes_key)
					encrypt_data=crypt_class.encrypt(reg(recv_data_json["sequence"]))
					# print reg(recv_data_json["sequence"])
					# print crypt_class.decrypt(b2a_hex(encrypt_data))
					tcp_client.sendall(pack_data(crypt_class.encrypt(reg(recv_data_json["sequence"]))))
					Aes_flags=True
			else:
				print "Aes_flags:->",Aes_flags
				datas=struct.unpack("!"+str(len(recv_data[8:]))+"s",recv_data[8:])
				# print "cryp data:->",datas
				print "Aes_key:::::->",Aes_key
				decode_recv_data=loads(crypt_class.decrypt(b2a_hex(datas[0])))
				print "decryp data:->",decode_recv_data
				if decode_recv_data["type"] == "cfg":
					tcp_client.sendall(pack_data(crypt_class.encrypt(ack_data(decode_recv_data["sequence"]))))
					print "---send cfg ack  data----"
				elif decode_recv_data["type"] == "ack":
					sleep(5)
					tcp_client.sendall(pack_data(crypt_class.encrypt(keepalive_data(decode_recv_data["sequence"]))))
					print "---send keepalive data----"
def keepalive_data(sequence):
	data={"type":"keepalive","sequence":int(sequence)+1,"mac":"08:60:6e:d4:58:1c","connected_time":"65535","signal_level":"3"}
	# data={"type":"keepalive","sequence":int(sequence)+1,"mac":"08:60:6e:d4:58:1c"}
	return dumps(data)	
def ack_data(sequence):
	data={"type":"ack","sequence":int(sequence),"mac":"08:60:6e:d4:58:1c"}
	# data={"type":"ack","sequence":int(sequence)}
	return dumps(data)
def reg(sequence):
	data={"type":"dev_reg","sequence":int(sequence)+1,
		"mac":"08:60:6e:d4:58:1c",
		"data":{"vendor":"netcore","model":"NAP871","url":"192.168.100.1","wireless":"yes"}}
	# data={"type":"dev_reg","mac":"08:60:6e:d4:58:1c"}
	return dumps(data)
def get_aes(dh_key,dh_p):
	prime="P4T2O6UlQe+bWTImuMKHNQ=="
	prime=int(binascii.hexlify(base64.b64decode(prime)), base=16)
	aes_key=pow(dh_key,prime,dh_p)
	print aes_key
	return str(hex(aes_key))[2:-1]
def dh_data(sequence):
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
def pack_data(data):
	print "data-len:",len(data)
	data=struct.pack("!II"+str(len(data))+"s",0x3f721fb5,len(data),data)
	return data
def quit(signum,frame):
	print "Ctr+C Stoping..."
	sys.exit()
if __name__ == '__main__':
	#discover_server()
	#tcp_client("192.168.0.1",20000)
	try:
		signal.signal(signal.SIGINT, quit)
		signal.signal(signal.SIGTERM, quit)

		t1=threading.Thread(target=discover_send,args=())
		t2=threading.Thread(target=discover_listen,args=())
		t1.setDaemon(True)
		t2.setDaemon(True)
		t1.start()
		t2.start()
		while 1:
			if AC_IP != "":
				print "get ac_ip ac_ip",AC_IP
				break
		t3=threading.Thread(target=tcp_client,args=(AC_IP,20000))
		t3.setDaemon(True)
		t3.start()
		while True:
			pass
	except Exception,exc:
		print exc