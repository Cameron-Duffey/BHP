import os
import socket

#Set host
HOST = '192.168.1.14'


def main():
    #check if windows machine
    if os.name == 'nt':
        socket_protocol = socket.IPPROTO_IP
    else:
        #if linux machine
        socket_protocol = socket.IPPROTO_ICMP
    
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    #setting port to 0 lets us sniff promiscuously
    sniffer.bind((HOST, 0))
    #grab IP header
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    
    print(sniffer.recvfrom(65565))
    
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        

if __name__ == '__main__':
    main()