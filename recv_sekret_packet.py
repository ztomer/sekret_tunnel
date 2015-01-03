#!/usr/bin/python3.4
# Waits for sekret packet 


import socket

UDP_IP = '127.0.0.1'
UDP_PORT = [123, 80]
BUFFER_SIZE = 1024

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT[0]))


print("Connection address: " + str(addr) )
while True: 
	data, addr = sock.recvfrom(BUFFER_SIZE)
	if not data: break
	print("received data: " + str(data) + " from " + addr );
	#conn.send(data) #echo


