from scapy.all import*
import time

from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.http import HTTP, HTTPRequest
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send

server_ip = "10.0.2.60"


if __name__ == '__main__':
    server_port = 40693  # server bind
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # bind the socket to a specific address and port
    server_address = ('127.0.0.1', server_port)
    print('starting up on {} port {}'.format(*server_address))
    sock.bind(server_address)

    # listen for incoming connections
    sock.listen(1)

    while True:
        # wait for a connection
        print('waiting for a connection')
        connection, client_address = sock.accept()
        try:
            print('connection from', client_address)

            # receive the HTTP request

            data = connection.recv(1024)
            data = data[-4:]
            if data != b'rUDP':
                data = data[1:]
            print("data= ", data)
            image = "image.png"
            if data == b"rUDP":
                print("if rUDP")
                image = "image_UDP.jpg"
                #send rUDP image
            elif data == b"TCP":
                print("if TCP")
                image = "image_TCP.jpg"
                #send TCP image

            # send the HTTP response with the image
            response = "HTTP/1.1 200 OK\r\nContent-Type: {}\r\n\r\n".format(image)
            connection.sendall(response.encode())
            print("send path to app")
            print("done with app")

        finally:
            # close the connection
            connection.close()