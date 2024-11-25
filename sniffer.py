import ipaddress
import os
import socket
import struct
import sys
import threading
import time

SUBNET = '192.168.1.0/24'
MESSAGE = 'PYTHONRULES!'

class IP:
    def __init__(self, buff=None):
        header = struct.unpack('<BBHHHBBH4s4s', buff)
        #first 4 bits of an IP packet are the version
        self.ver = header[0] >> 4
        
        #next 4 bits of an IP packet is the header length
        self.ihl = header[0] & 0xF
        
        #next 8 bits of an IP packet is the type of service
        self.tos = header[1]
        
        #next 16 bits of an IP packet is the total length of the
        self.len = header[2]
        
        #next 16 bits of an IP packet is the ID
        self.id = header[3]
        
        #next 13 bits of an IP packet is the fragment offset
        self.offset = header[4]
        
        #next 8 bits of an IP packet is the time to live(TTL)
        self.ttl = header[5]
        
        #next 8 bits of an IP packet is for the protocol
        self.protocol_num = header[6]
        
        #next 16 bits of an IP packet is for the header checksum
        self.sum = header[7]
        
        #next 32 bits of an IP packet is for the source address
        self.src = header[8]
        
        #next 32 bits of an IP packet is for the destination address
        self.dst = header[9]
        
        #human readable IP addresses
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)
        
        #map protocol constants to tneir names
        self.protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        try:
            self.protocol = self.protocol_map(self.protocol_num)
        except Exception as e:
            print('%s No protocol for %s' % (e, self.protocol_num))
            self.protocol = str(self.protocol_num)

class ICMP:
    def __init__(self, buff):
        header = struct.unpack('<BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]

def udp_sender():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for ip in ipaddress.ip_network(SUBNET).hosts():
            time.sleep(1)
            #print('+', 'end='')
            sender.sendto(bytes(MESSAGE, 'utf8'), (str(ip), 65212))

class Scanner:
    def __init__(self, host):
        self.host = host
        if os.name == 'nt':
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP
            
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        #setting port to 0 lets us sniff promiscuously
        self.socket.bind((host, 0))
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        print('Promiscuous mode....')
        if os.name == 'nt':
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    
    def sniff(self):
        hosts_up = set([f'{str(self.host)} *'])
        try:
            while True:
                #print('+', end='')
                raw_buffer = self.socket.recvfrom(65535, [0])
                ip_header = IP(raw_buffer[0:20])
                if ip_header.ihl == 'ICMP':
                    offset = ip_header.ihl = 4
                    buf = raw_buffer[offset:offset + 8]
                    icmp_header = ICMP(buf)
                    
                    if icmp_header.code == 3 and icmp_header.type == 3:
                        if ipaddress.ip_address(ip_header.src_address) in ipaddress.IPv4Network(SUBNET):
                            if raw_buffer[len(raw_buffer) - len(MESSAGE): ] == bytes(MESSAGE, 'utf8'):
                                hosts_up.add(str(ip_header.src_address))
                                print(f'Host Up: {str(ip_header.src_address)}')
        #handle CTRL+C
        except KeyboardInterrupt:
            if os.name == 'nt':
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            
            print('\nUser Interuppted.')
            if hosts_up:
                print(f'\n\nSummary: Hosts up on {SUBNET}')
            for host in sorted(hosts_up):
                print(f'{host}')
            print('')
            sys.exit()
               
if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = '192.168.1.14'
    s = Scanner(host)
    time.sleep(10)
    t = threading.Thread(target=udp_sender)
    t.start()
    s.sniff