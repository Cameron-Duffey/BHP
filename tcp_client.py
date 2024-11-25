import socket

target_host = '127.0.0.1'
target_port = 9998

#Socket = IP address + port

#Create a socket object
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#Connect client to target
client.connect((target_host, target_port))

#Send some data 
client.send(b'GET / HTTP/1.1\r\nHOST:google.com\r\n\r\n')

#Recieve some data
response = client.recv(4096)

print(response)
client.close()