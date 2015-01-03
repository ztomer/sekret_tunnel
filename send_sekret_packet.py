#!/usr/bin/python3.4

# Sends magic UDP packet for nethook module
# tested using python 3.4, Ubuntu 14.04
#
# NOTE: python 2.7 sends UDP packets as string, python 3+ sends packets
# as binary. This script assumes use of python 3.4

import socket
import struct

#TARGET_UDP_PORT = 123
TARGET_UDP_PORT = 80
TARGET_IP       = "127.0.0.1"
SOURCE_IP_HEX	= 0x7F000001 # 127.0.0.1
# signature          = 0xAB007B1F
not_signature = 0xAAAAAAAA

# packet payload 

port_number     = 80
payload     	= b"Top Sekret password iz: #####"

# create TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

try:
    # Create binary packet - 
    # type   - network,
    # uint32 - signature
    # uint32 - msg_index
    # uint32 - source address (ip)	
    # uint16 - destination port
    # uint16 - padding
    # uint32 - packet number (from total)
    # uint32 - packet total number 
    # uint32 - payload size
    # char[] - payload 
    # the 16bit port_number is padded on the target port
    packet_bytes = struct.pack('!IIIHHIII'+str(len(payload))+'s',
    	not_signature,
    	1,
    	SOURCE_IP_HEX,
    	port_number,
    	0,
    	1,
    	1,
    	len(payload),
    	payload)

    print("sending Sekret udp packet")
    print("--")
    sock.sendto(packet_bytes, (TARGET_IP, TARGET_UDP_PORT))
    print("--")
    print("Sekret udp packet sent")
    
except Exception as inst:
    print("Err: " + str(type(inst)) + " " +  str(inst.args))

sock.close()







