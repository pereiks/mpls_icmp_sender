from socket import *
import fcntl
import struct
import random
import time
import select
import itertools
import threading
import argparse
import pexpect
import StringIO
import re
import ping  # Local file ping.py


parser = argparse.ArgumentParser(description='Test Packets trtansmission \
between PE devices in MPLS domain')
parser.add_argument('targets',
                    metavar='<filename>',
                    type=str,
                    help='File with loopbacks, one per line')
parser.add_argument('lsr',
                    metavar='<LSR_IP>',
                    type=str,
                    help='Nexthop for MPLS packets')
parser.add_argument('--proto',
                    metavar='<telnet|ssh>',
                    type=str,
                    help='Protocol, used for connection to LSR, \
default is telnet',
                    choices=['telnet', 'ssh'],
                    default='telnet')
parser.add_argument('--login',
                    metavar='<user>',
                    type=str,
                    help='Username on LSR, default is cisco',
                    default='cisco')
parser.add_argument('--password',
                    metavar='<password>',
                    type=str,
                    help='Password on LSR, default is cisco',
                    default='cisco')
parser.add_argument('--size',
                    metavar='<size>',
                    type=int,
                    help='Packet size, default is 1500',
                    default=1500)
parser.add_argument('--dscp',
                    metavar='<value>',
                    type=int,
                    help='DSCP value in IP packets, default is 0',
                    default=0)
parser.add_argument('--queue_size',
                    metavar='<size>',
                    type=int,
                    help='Receive queue size, default is 20 packets',
                    default=20)
parser.add_argument('--retry',
                    metavar='<count>',
                    type=int,
                    help='Number of tries, if packet is lost, for each packet',
                    default=2)
parser.add_argument('--verbose',
                    action='store_true',
                    help='Verbose output',
                    default=False)
parser.add_argument('--showreceived',
                    action='store_true',
                    help='Show received packets',
                    default=False)
args = parser.parse_args()

verbose = False
LSR = args.lsr
PROTO = args.proto
USER = args.login
PASS = args.password
PACKETSIZE = args.size
RETRY_COUNT = args.retry
VERBOSE = args.verbose
SHOW_RECEIVED = args.showreceived
if args.dscp in range(0, 64):
    DSCP = args.dscp
else:
    print "Incorrect DSCP"
    exit(-1)
TARGETS_FILE = False
ip_regexp = '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\-' +\
            '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
if re.match(ip_regexp, args.targets):
    TARGETS = args.targets.split('-')
else:
    TARGETS_FILE = args.targets
PACKETS_IN_TRANSIT = args.queue_size


def get_labels(lsr, user, password, proto):
    if proto == 'telnet':
        p = pexpect.spawn('telnet '+lsr)
        p.expect('sername')
        p.sendline(user)
        p.expect('ssword')
        p.sendline(password)
    elif proto == 'ssh':
        p = pexpect.spawn('ssh -l %s %s' % (user, lsr))
        index = p.expect(['ssword:', 'continue connecting'])
        if index == 1:
            p.sendline("yes")
            p.expect('ssword:')
        p.sendline(password)
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
        if re.match('^[0-9]+\s.*/32', line):
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
    try:
        result = s.send(ethernet_packet + payload)
    except error as e:
        print "Error: %s" % e
        s.close()
        return -1
    s.close()
    return result


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
        tos = int(struct.unpack(">B", recPacket[1:2])[0])
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
            send_list[pkt_id]['tos'] = tos
            if SHOW_RECEIVED:
                print "Packet %i with (SRC=>MIDPOINT(LABEL)=>DST)\
=(%s=>%s(%i)=>%s) TOS=%i rcvd in %5.3fms" % \
                    (pkt_id, SRC, send_list[pkt_id]['mid'],
                        send_list[pkt_id]['label'], send_list[pkt_id]['dst'],
                        tos, rtt)
    my_socket.close()


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
    DATA = 'ff' * (size-28)
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


if VERBOSE:
    print "Determing interface name...",
INTERFACE = get_iface(LSR)  # Get outgoing interface name
if INTERFACE is False:
    print "LSR is not connected or iface is down"
    exit(-1)
if VERBOSE:
    print INTERFACE
send_list = []  # Initial Send List
if VERBOSE:
    print "Determing SRC IP...",
SRC = get_ip_address(INTERFACE)  # Interface IP
if VERBOSE:
    print SRC
if VERBOSE:
    print "Determing SRC MAC...",
SRC_MAC = get_mac_address(INTERFACE)  # Interface MAC
if VERBOSE:
    print SRC_MAC
if VERBOSE:
    print "Determing LSR MAC by sending ARP...",
DST_MAC_INT = send_arp(INTERFACE, SRC, SRC_MAC, LSR)
if DST_MAC_INT is False:
    print "ARP reply not received"
    exit(-1)
if VERBOSE:
    print DST_MAC_INT
if VERBOSE:
    print "Trying to parse label list from LSR...",
LABELS = get_labels(LSR, USER, PASS, PROTO)
if TARGETS_FILE is not False:
    try:
        TARGETS = [line.strip() for line in open(TARGETS_FILE, 'r')]
    except IOError as e:
        print "Error: %s" % e.strerror
        exit(-1)
if VERBOSE:
    print "done"
if VERBOSE:
    print "Checking if targets is alive by pinging them with size %i..." % PACKETSIZE
ALIVE_TARGETS = []
for target in TARGETS:
    status = ping.quiet_ping(target, psize=PACKETSIZE-20, count=2)
    if status[0] < 100:
        if VERBOSE:
            print "\tTarget %s is alive" % target
        ALIVE_TARGETS.append(target)
    else:
        if VERBOSE:
            print "\tTarget %s is dead" % target
if VERBOSE:
    print "Totally %i targets alive" % len(ALIVE_TARGETS)
# Create all possible variations of targets
if VERBOSE:
    print "Creating permutation list from alive targets list...",
for target in itertools.permutations(ALIVE_TARGETS, 2):
    IDENTIFIER = random.randint(0, 0xffff)
    SEQNUM = random.randint(0, 0xffff)
    try:  # Search for loopback in LSDB
        label = int(next(i[0] for i in LABELS if i[1] == target[0]))
    except StopIteration:  # Loopback not found in LSDB on LSR, set it to Explicit Null
        label = 0
    send_list.append({'mid': target[0], 'label': label, 'dst': target[1],
                      'id': IDENTIFIER, 'seq': SEQNUM, 'rcvd': False,
                      'ts': 0, 'rtt': -1, 'send_cnt': 0})
if VERBOSE:
    print "done"
completed = False  # Set completed flag for thread to False
# Start ICMP receive thread
if VERBOSE:
    print "Starting receive thread..."
pingRcvThread = threading.Thread(target=receive_ping)
pingRcvThread.start()
if VERBOSE:
    print "done"

# Send ICMP to targets is send_list
if VERBOSE:
    print "Start sending packets (%i tries)..." % RETRY_COUNT
iteration = 1
while len([i for i in send_list if not i['rcvd']
           and i['send_cnt'] < RETRY_COUNT]) > 0:
    nodes_left = len([i for i in send_list if not i['rcvd']
                     and i['send_cnt'] < RETRY_COUNT])
    if VERBOSE:
        print "\tTry #%i: %i nodes left" % (iteration, nodes_left)
    for pkt_id, pkt in enumerate(send_list):
        if not pkt['rcvd']:
            while len([i for i in send_list if i['ts'] >= 0
                      and time.time()-i['ts'] < 2
                      and not i['rcvd']]) > PACKETS_IN_TRANSIT:
                time.sleep(0.1)
            ethernet_packet = create_l2_header(SRC_MAC, DST_MAC_INT, pkt['label'])
            icmp_header = create_l4_header(pkt['id'], pkt['seq'], PACKETSIZE)
            ipv4_header = create_l3_header(SRC, pkt['dst'], len(icmp_header), DSCP)
            send_list[pkt_id]['ts'] = time.time()
            send_list[pkt_id]['send_cnt'] = send_list[pkt_id]['send_cnt'] + 1
            sendeth(pack(ethernet_packet), pack(ipv4_header + icmp_header),
                    INTERFACE)
    time.sleep(2)  # Wait for all ICMP replies
    iteration = iteration + 1

if VERBOSE:
    print "All done"
completed = True  # Set Thread flag to True
# Pkt counters
rcvd = 0
lost = 0
# Print results
for pkt_id, pkt in enumerate(send_list):
    if pkt['rcvd'] is False:
        print "====> Packet %i with (SRC=>MIDPOINT(LABEL)=>DST)=\
(%s=>%s(%i)=>%s) lost" % \
            (pkt_id, SRC, pkt['mid'], pkt['label'], pkt['dst'])
        lost += 1
    elif pkt['rcvd'] is True:
        rcvd += 1
print "Summary: Rcvd: %i, Lost: %i" % (rcvd, lost)
