from scapy.all import*
import time

from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.http import HTTP, HTTPRequest
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send
import requests
import socket
import PIL
from PIL import Image


global ip, domain, server_ip, buffer, max_window, client_ip, client_port, addr_image, count, client_port_tcp, server_port, client_port_rudp, client_cho
ip = "10.0.2.50"  # ip APP
domain = "www.myApp.com"  # domain APP
server_ip = "10.0.2.60"
count = 0
client_port_tcp = 30308  # app bind tcp
server_port = 30693  # server bind
udp_port = 40308  # app bind rudp
client_port_rudp = 40693  # client bind rudp


# ----------rUDP related code------------------

def get_request_rUDP(pkt):
    global ip, domain, server_ip, buffer, max_window, client_ip, client_port
    client_ip = pkt[IP].src
    client_port = pkt[UDP].sport
    http_payload = str(pkt[Raw].load)
    fields = http_payload.split(",")
    max_window = int(fields[2].split(":")[1])  # the window from the client
    seq_num = fields[3].split(":")[1].split("'")[0]
    print("max window of client = ", max_window)
    # send ack about the request from the client
    time.sleep(1)

    ip1 = IP(dst=pkt[IP].src, src=ip)
    udp = UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
    http = "HTTP/4 200 OK,seq: {}".format(seq_num)
    ack_pkt = ip1 / udp / http
    send(ack_pkt)
    get_image()
    image_to_client()


# send the image to the client in socket of UDP
def image_to_client():
    global max_window, client_ip, client_port_rudp, addr_image, udp_port

    # Define the IP address and port number of the receiver
    udp_ip = "127.0.0.1"
    buffer_size = 1000  # the min window sent
    max_window = (max_window - 400)
    # Open the image file in binary mode
    with open(addr_image, "rb") as f:
        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((udp_ip, udp_port))
        sock.setblocking(False)  # socket not blocking for timeout

        # Read the image file in chunks and send them over UDP
        count = 0
        file_pos = 0
        seq_num = 0
        seq_ack = -1
        while True:
            if seq_num == (seq_ack+1):  # if we got ack send new data
                f.seek(file_pos)
                # print(f.seek(file_pos))
                chunk = f.read(buffer_size)
                # print(chunk)
                print("send new packet, buffer size= ", buffer_size)
                if not chunk:
                    # End of file reached
                    print("no more data to send")
                    break
            # Send the chunk over UDP
            client_address = (udp_ip, client_port_rudp)
            seq_data = str(seq_num) + "seq!!!!!"
            sock.sendto(seq_data.encode() + chunk, client_address)
            print("seq_num", seq_num)
            num = 5  # for timeout
            data = False
            print("wait for ack")
            while num:
                # print("num = ", num)
                try:
                    data, addr = sock.recvfrom(80)
                    # print("data = ", data)
                except socket.error:
                    # No data available to receive
                    pass
                time.sleep(2)  # timeout
                num -= 1
                if data:
                    seq_ack = (data.decode("utf-8")).split("ack:")[1].split("'")[0]
                    seq_ack = int(seq_ack)
                    print("ack seq:", seq_ack)
                    if seq_num == seq_ack and (buffer_size * 2) <= max_window:
                        count = 0
                        print("got ack! double the size of buffer!")
                        buffer_size = buffer_size * 2
                        file_pos = f.tell()
                        seq_num += 1
                    elif seq_num == seq_ack and buffer_size <= max_window:
                        count = 0
                        print("got ack! buffer = max client window!")
                        buffer_size = max_window
                        file_pos = f.tell()
                        seq_num += 1
                    elif seq_num != seq_ack and count < 3:
                        print("\ntimeout!!! buffer decreases by half, count-", count)
                        if buffer_size >= 2000:
                            buffer_size = int(buffer_size / 2) + 1
                        else:
                            buffer_size = 1000
                        count += 1
                        chunk = chunk[:buffer_size]
                    else:
                        print("\n3 timeout!!! buffer decreases to min value- 1000. count-", count)
                        count = 0
                        buffer_size = 1000
                        chunk = chunk[:buffer_size]
                    break

            if not data:
                print("didn't recv")

        # after we sent all the data, send to client final message
        chunk = "final"
        sock.sendto(chunk.encode(), client_address)
        # Close the socket
        sock.close()
        print("done with client")


# ----------TCP related code------------------

def get_request_TCP():
    global addr_image, client_port_tcp
    # create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # bind the socket to a specific address and port
    server_address = ('127.0.0.1', client_port_tcp)
    print('starting up on {} port {}'.format(*server_address))
    sock.bind(server_address)
    # listen for incoming connections
    sock.listen(1)
    # wait for a connection
    print('waiting for a connection')
    connection, client_address = sock.accept()
    try:
        print('connection from', client_address)
        # receive the HTTP request
        data = connection.recv(1024)
        print("got from client = ", data)
        if b'image' in data:
            get_image()
            # send the HTTP response with the image
            with open(addr_image, 'rb') as f:
                # print("addr_image = ", addr_image)
                response = b"HTTP/1.1 200 OK\r\nContent-Type: image/jpg\r\n\r\n"
                f.seek(0)
                res2 = f.read()
                # print("res2 = ", res2)
            connection.sendall(response)
            connection.sendall(res2)
            print("send all the image to client")

    finally:
        print("finally")
        # close the connection
        connection.close()
        sock.close()


# ----------SERVER related code------------------

# getting path of image from server in TCP
def get_image():
    global addr_image, server_port, client_cho

    # create a TCP socket
    socket_app_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("\nconnect to sever")
    # connect the socket to the server's address and port
    server_address = ('127.0.0.1', server_port)
    print('connecting to ', server_address)
    socket_app_server.connect(server_address)
    # send an HTTP GET request for the image

    # request = b"GET /image HTTP/1.1\r\nHost: www.myApp.com\r\n\r\n"
    request = b"GET /image HTTP/1.1\r\nHost: www.myApp.com\r\n\r\n" + client_cho.encode()
    socket_app_server.sendall(request)
    print("send get path of image to server: ", request)
    print("wait to recv from server")
    # receive the response and save it as an image file
    addr_image = socket_app_server.recv(44)
    addr_image = addr_image.decode('utf-8').split(": ")[1]
    addr_image = addr_image[:13]
    print("addr image = ", addr_image)

    # close the socket
    socket_app_server.close()
    print("done with server\n")


if __name__ == '__main__':
    global client_cho
    print("app on")
    while True:
        pkt = sniff(filter="port 80 and dst host " + ip, count=1)[0]
        print("got pkt")
        if pkt.haslayer(UDP):
            print("got pkt UDP")
            client_cho = "rUDP"
            get_request_rUDP(pkt)
        elif pkt.haslayer(TCP):
            image_ack = IP(dst=pkt[IP].src, src=pkt[IP].dst) / TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags="A", ack=(pkt[TCP].seq + 1))
            send(image_ack)
            client_cho = "TCP"
            print("got pkt TCP")
            get_request_TCP()
