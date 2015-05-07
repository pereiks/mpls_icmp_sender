from socket import *
import struct
import random
import time
import select

def sendeth(ethernet_packet, payload, interface = "eth1"):
	"""Send raw Ethernet packet on interface."""
	s = socket(AF_PACKET, SOCK_RAW)

	# From the docs: "For raw packet
	# sockets the address is a tuple (ifname, proto [,pkttype [,hatype]])"
	s.bind((interface, 0))
	return s.send(ethernet_packet + payload)

def receive_one_ping(my_socket, ID, timeout):
	"""
	receive the ping from the socket.
	"""
	timeLeft = timeout
	timeSent=time.time()
	while True:
		startedSelect = time.time()
		whatReady = select.select([my_socket], [], [], timeLeft)
		howLongInSelect = (time.time() - startedSelect)
		if whatReady[0] == []: # Timeout
			return -1	    
		recPacket = ''
		recPacket, addr = my_socket.recvfrom(10000)
		icmpHeader = recPacket[20:28]
		print repr(recPacket[0:60])
		type, code, checksum, packetID, sequence = struct.unpack("bbHHH", icmpHeader)
		print [type, code, checksum, packetID, sequence]
		if packetID == ID:
			bytesInDouble = struct.calcsize("d")
			#timeSent = struct.unpack("d", recPacket[28:28 + bytesInDouble])[0]
			timeReceived = time.time()
			return timeReceived - timeSent	    

		timeLeft = timeLeft - howLongInSelect
		if timeLeft <= 0:
			return -1

def pack(byte_sequence):
	return b"".join(map(chr, byte_sequence))

def str2hex(str):
	result = []
	for i in xrange(0,len(str),2):
		char = str[i:i+2] 
		result.append(int(char,16))
	return result

def ipv4_checksum(hex_str):
	step1sum=0
	step2sum=0
	for i in xrange(0,len(hex_str),4):
		step1sum+=int(hex_str[i:i+4],16)
		if i+4<len(hex_str) and i+8>len(hex_str):
			step1sum+=int(hex_str[i+4:],16)
	#print "STEP 1(ADD):",hex(step1sum)
	step2str = '{0:08x}'.format(step1sum)
	step2sum = int(step2str[:4],16)+int(step2str[4:],16)
	#print "STEP 2(ADDITION): ",hex(step2sum)
	step3sum = ~step2sum & (2**16-1)
	#print "STEP 3(INVERT): ",hex(step3sum)
	return step3sum

# ETHERNET HEADER PARAMETERS
SRC_MAC = str2hex('fa163eaaa081')
DST_MAC = str2hex('fa163e778e2b')
ETHERTYPE = str2hex('8847')

# MPLS HEADER PARAMETERS
LABEL=18
EXP = 0
BOS = 0b1 
TTL = 255
MPLS_HEADER = '%05x%x%02x' %(LABEL,EXP+BOS,TTL)
ethernet_packet = DST_MAC+SRC_MAC+ETHERTYPE+str2hex(MPLS_HEADER)

#ICMP Header
TYPE=8
CODE=0
ICMP_CHECKSUM=0
DATA='ff' * 1000
IDENTIFIER=random.randint(0,0xffff)
SEQNUM=random.randint(0,0xffff)
icmp_header = '{0:02x}{1:02x}{2:04x}{3:04x}{4:04x}{5:s}'.format(TYPE,CODE,ICMP_CHECKSUM,\
				IDENTIFIER,SEQNUM,DATA)
ICMP_CHECKSUM='{0:04x}'.format(ipv4_checksum(icmp_header))
#print ICMP_CHECKSUM
icmp_ping = str2hex(icmp_header[:4] + ICMP_CHECKSUM + icmp_header[8:])
#print icmp_ping

# IP Header
VERSION=4
IHL=5
TOS=0
TOTAL_LENGTH = 20 + len(icmp_ping)
IDENTIFICATION = random.randint(0,255)
FLAGS = 0b010
FRAG_OFFSET=0
TTL=255
PROTOCOL = 1
SRC='10.0.0.5'
SRC_DEC=[int(x) for x in SRC.split('.')]
DST='192.168.0.3'
DST_DEC=[int(x) for x in DST.split('.')]
CHECKSUM = 0

ipv4_header= '%x%x%02x%04x%04x%04x%02x%02x%04x' %(VERSION,IHL,TOS,TOTAL_LENGTH,\
		IDENTIFICATION,int('{0:03b}{1:013b}'.format(FLAGS,FRAG_OFFSET),2),\
		TTL,PROTOCOL,CHECKSUM)+'{0:02x}{1:02x}{2:02x}{3:02x}'.format(*SRC_DEC)+\
		'{0:02x}{1:02x}{2:02x}{3:02x}'.format(*DST_DEC)
CHECKSUM='{0:04x}'.format(ipv4_checksum(ipv4_header))
ipv4_header = str2hex(ipv4_header[:20]+CHECKSUM+ipv4_header[24:])


payload = "".join(map(chr, ipv4_header + icmp_ping))

# Construct Ethernet packet with an IPv4 ICMP PING request as payload
icmp = getprotobyname("icmp")
try:
	my_socket = socket(AF_INET,SOCK_RAW,icmp)
except:
	print "Error!"
r = sendeth(pack(ethernet_packet),pack(ipv4_header + icmp_ping))
print("Sent Ethernet w/IPv4 ICMP PING (%i,%i) payload of length %d bytes" % (IDENTIFIER,SEQNUM,r))
x = str(receive_one_ping(my_socket,IDENTIFIER,10))
print "Received in ",x," seconds"

