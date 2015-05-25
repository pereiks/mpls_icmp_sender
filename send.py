from socket import *
import fcntl
import struct
import random
import time
import select
import itertools
import threading

LSR = '10.0.0.6'
PROTO = 'telnet'
USER = 'cisco'
PASS = 'cisco'
ICMPSIZE = 1000
DSCP = 40


def get_targets(lsr, user, password, proto):
    import pexpect
    import StringIO
    import re
    if proto == 'telnet':
        p = pexpect.spawn('telnet '+lsr)
        p.expect('sername')
        p.sendline(user)
    elif proto == 'ssh':
        p = pexpect.spawn('ssh '+user+'@'+lsr)
    p.expect('ssword')
    p.sendline(password)
    p.expect('>')
    p.send('enable\r'+password+'\r')
    p.expect('#')

    fh = StringIO.StringIO()
    p.logfile_read = fh
    p.send('terminal length 0\rshow mpls forwarding | i ^[0-9].*/32\r')
    p.send('exit\r')
    p.expect('Connection')
    p.close()
    contents = fh.getvalue()
    targets = []
    expr = r'^([0-9]+).+\s([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\/32'
    for line in contents.split('\n'):
        if re.match('^[0-9].*/32', line):
            targets.append(re.findall(expr, line)[0])
    return targets


def get_iface(dst):
    dst_int = struct.unpack('>i', inet_aton(dst))[0]
    candidates = []
    with open('/proc/net/route') as fh:
        for line in fh.readlines()[1:]:
            splitted_line = line.split('\t')
            if splitted_line[3] == '0001':
                start_ip_int = int(splitted_line[1][6:8] +
                                   splitted_line[1][4:6] +
                                   splitted_line[1][2:4] +
                                   splitted_line[1][0:2], 16)
                mask_int = int(splitted_line[7][6:8] +
                               splitted_line[7][4:6] +
                               splitted_line[7][2:4] +
                               splitted_line[7][0:2], 16)
                end_ip_int = start_ip_int + 0xffffffff - mask_int
                if dst_int >= start_ip_int and dst_int <= end_ip_int:
                    return splitted_line[0]
    return False


def send_arp(iface, src_ip, src_mac, dst_ip):
    eth_hdr = struct.pack("!6s6s2s", '\xff\xff\xff\xff\xff\xff',
                          src_mac.decode('hex'),
                          '\x08\x06')
    arp_hdr = struct.pack("!2s2s1s1s2s", '\x00\x01', '\x08\x00', '\x06',
                          '\x04', '\x00\x01')
    arp_sender = struct.pack("!6s4s", src_mac.decode('hex'), inet_aton(src_ip))
    arp_target = struct.pack("!6s4s", '\x00\x00\x00\x00\x00\x00',
                             inet_aton(dst_ip))
    s = socket(AF_PACKET, SOCK_RAW, 0x0806)
    s.settimeout(0.5)
    s.bind((iface, 0x0806))
    s.send(eth_hdr+arp_hdr+arp_sender+arp_target)
    try:
        return list(struct.unpack(">BBBBBB", s.recv(2048)[6:12]))
    except timeout:
        return False


def get_ip_address(ifname):
    s = socket(AF_INET, SOCK_DGRAM)
    ipaddr = inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])
    s.close()
    return ipaddr


def get_mac_address(ifname):
    s = socket(AF_INET, SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(),
                       0x8927,
                       struct.pack('256s', ifname[:15])
                       )[18:24]
    s.close()
    return ''.join(['%02x' % ord(char) for char in info])


def dscp2tos(dscp):
    tos = dscp * 0b100
    return tos


def sendeth(ethernet_packet, payload, interface):
    """Send raw Ethernet packet on interface."""
    s = socket(AF_PACKET, SOCK_RAW)
    s.bind((interface, 0))
    return s.send(ethernet_packet + payload)


def receive_ping():
    """
    receive the ping from the socket.
    """
    icmp = getprotobyname("icmp")
    my_socket = socket(AF_INET, SOCK_RAW, icmp)
    while completed is False:
        whatReady = select.select([my_socket], [], [], 0.5)
        if whatReady[0] == []:  # Timeout
            continue
        elif completed is True:
            break
        recPacket, addr = my_socket.recvfrom(10000)
        icmpHeader = recPacket[20:28]
        timeRcvd = time.time()
        type, code, checksum, packetID, sequence = struct.unpack(">bbHHH",
                                                                 icmpHeader)
        pkt_id = next((pkt_id for pkt_id, i in enumerate(send_list)
                      if i['id'] == packetID and i['seq'] == sequence
                      and i['dst'] == addr[0]), False)
        if pkt_id is not False:
            rtt = time.time() - send_list[pkt_id]['ts']
            send_list[pkt_id]['rtt'] = rtt
            send_list[pkt_id]['rcvd'] = True


def pack(byte_sequence):
    """ Convert int to bytes """
    return b"".join(map(chr, byte_sequence))


def str2hex(str):
    """ convert hex string to int list """
    result = []
    for i in xrange(0, len(str), 2):
        char = str[i:i+2]
        result.append(int(char, 16))
    return result


def ipv4_checksum(hex_str):
    """ calculate IPv4 checksum """
    step1sum = 0
    step2sum = 0
    for i in xrange(0, len(hex_str), 4):
        step1sum += int(hex_str[i:i+4], 16)
        if i+4 < len(hex_str) and i+8 > len(hex_str):
            step1sum += int(hex_str[i+4:], 16)
    #print "STEP 1(ADD):",hex(step1sum)
    step2str = '{0:08x}'.format(step1sum)
    step2sum = int(step2str[:4], 16)+int(step2str[4:], 16)
    #print "STEP 2(ADDITION): ",hex(step2sum)
    step3sum = ~step2sum & (2**16-1)
    #print "STEP 3(INVERT): ",hex(step3sum)
    return step3sum


def create_l2_header(src, dst_int, label):
    """ Create L2+MPLS header """
    # ETHERNET HEADER PARAMETERS
    ETHERTYPE = '8847'
    # MPLS HEADER PARAMETERS
    EXP = 0
    BOS = 0b1
    TTL = 255
    MPLS_HEADER = '%05x%x%02x' % (label, EXP+BOS, TTL)
    return dst_int+str2hex(src+ETHERTYPE+MPLS_HEADER)


def create_l4_header(id, seq, size):
    """ Create ICMP header """
    TYPE = 8
    CODE = 0
    ICMP_CHECKSUM = 0
    DATA = 'ff' * size
    icmp_header = '{0:02x}{1:02x}{2:04x}'.format(TYPE, CODE, ICMP_CHECKSUM) +\
                  '{0:04x}{1:04x}{2:s}'.format(id, seq, DATA)
    ICMP_CHECKSUM = '{0:04x}'.format(ipv4_checksum(icmp_header))
    #print ICMP_CHECKSUM
    return str2hex(icmp_header[:4] + ICMP_CHECKSUM + icmp_header[8:])


def create_l3_header(SRC, DST, l4_len, dscp):
    """ Create IP header """
    VERSION = 4
    IHL = 5
    TOTAL_LENGTH = 20 + l4_len
    IDENTIFICATION = random.randint(0, 255)
    FLAGS = 0b010
    FRAG_OFFSET = 0
    TTL = 255
    PROTOCOL = 1
    SRC_DEC = [int(x) for x in SRC.split('.')]
    DST_DEC = [int(x) for x in DST.split('.')]
    CHECKSUM = 0
    TOS = dscp2tos(dscp)

    ipv4_header = '%x%x%02x%04x%04x%04x%02x%02x%04x' % \
        (VERSION, IHL, TOS, TOTAL_LENGTH, IDENTIFICATION,
         int('{0:03b}{1:013b}'.format(FLAGS, FRAG_OFFSET), 2),
         TTL, PROTOCOL, CHECKSUM) + \
        '{0:02x}{1:02x}{2:02x}{3:02x}'.format(*SRC_DEC) + \
        '{0:02x}{1:02x}{2:02x}{3:02x}'.format(*DST_DEC)
    CHECKSUM = '{0:04x}'.format(ipv4_checksum(ipv4_header))
    return str2hex(ipv4_header[:20]+CHECKSUM+ipv4_header[24:])


INTERFACE = get_iface(LSR)  # Get outgoing interface name
if INTERFACE is False:
    print "LSR is not connected or iface is down"
    exit(-1)
send_list = []  # Initial Send List
SRC = get_ip_address(INTERFACE)  # Interface IP
SRC_MAC = get_mac_address(INTERFACE)  # Interface MAC
DST_MAC_INT = send_arp(INTERFACE, SRC, SRC_MAC, LSR)
if DST_MAC_INT is False:
    print "ARP reply not received"
    exit(-1)
TARGETS = get_targets(LSR, USER, PASS, PROTO)
# Create all possible variations of targets
for target in itertools.permutations(TARGETS, 2):
    IDENTIFIER = random.randint(0, 0xffff)
    SEQNUM = random.randint(0, 0xffff)
    send_list.append({'label': int(target[0][0]), 'dst': target[1][1],
                     'id': IDENTIFIER, 'seq': SEQNUM, 'rcvd': False,
                     'ts': 0, 'rtt': -1})

completed = False  # Set completed flag for thread to False
# Start ICMP receive thread
pingRcvThread = threading.Thread(target=receive_ping)
pingRcvThread.start()

# Send ICMP to targets is send_list
for pkt_id, pkt in enumerate(send_list):
    while len([i for i in send_list if i['ts'] > 0
              and time.time()-i['ts'] < 2
              and not i['rcvd']]) > 10:
        time.sleep(0.1)
    ethernet_packet = create_l2_header(SRC_MAC, DST_MAC_INT, pkt['label'])
    icmp_header = create_l4_header(pkt['id'], pkt['seq'], ICMPSIZE)
    ipv4_header = create_l3_header(SRC, pkt['dst'], len(icmp_header), DSCP)
    send_list[pkt_id]['ts'] = time.time()
    sendeth(pack(ethernet_packet), pack(ipv4_header + icmp_header),
            INTERFACE)

time.sleep(2)  # Wait for all ICMP replies
completed = True  # Set Thread flag to True
# Pkt counters
rcvd = 0
lost = 0
# Print results
for pkt_id, pkt in enumerate(send_list):
    if pkt['rcvd'] is False:
        print "====> Packet %i with (SRC=>LABEL=>DST)=(%s=>%i=>%s) lost" % \
            (pkt_id, SRC, pkt['label'], pkt['dst'])
        lost += 1
    elif pkt['rcvd'] is True:
        print "Packet %i with (SRC=>LABEL=>DST)=(%s=>%i=>%s) \
rcvd in %5.3fms" % \
            (pkt_id, SRC, pkt['label'], pkt['dst'], pkt['rtt'])
        rcvd += 1
print "Summary: Rcvd: %i, Lost: %i" % (rcvd, lost)
