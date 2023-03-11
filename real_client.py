from scapy.all import *
import socket
import time
import PIL

from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.http import HTTP, HTTPRequest
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send
from PIL import Image
import json
import pickle

global client_ip, dns_ip, ip_app, seq_num, ack, buffer_size, client_port_tcp, udp_port, client_port_rudp

client_port_tcp = 25553  # app bind
client_port_rudp = 18848  # client bind rudp



# -------DHCP related code---------------

# create and send dhcp_discover in broadcast
def dhcp():
    print("to DHCP")
    dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                    IP(src='0.0.0.0', dst='255.255.255.255') / \
                    UDP(sport=68, dport=67) / \
                    BOOTP(chaddr="08:00:27:13:c2:0f", xid=0x11111111) / \
                    DHCP(options=[("message-type", "discover"), "end"])
    time.sleep(1)
    sendp(dhcp_discover)
    print("sent DISCOVER")

    # wait for an offer packet from the DHCP server in port 67
    sniff(filter="udp and port 67", prn=dhcp_request, count=1, iface="enp0s3")


# when we got an offer we create and send dhcp_request in broadcast
def dhcp_request(pkt):
    print("got OFFER")
    # save the client and dns ip
    global client_ip, dns_ip
    client_ip = pkt[BOOTP].yiaddr
    dns_ip = pkt[DHCP].options[3][1]

    # probably there were no available ips
    if client_ip == "0.0.0.0":
        print("something got wrong")
        return

    print("dns:", dns_ip)
    print("client:", client_ip)

    # create and send dhcp_request in broadcast
    dhcp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                   IP(src="0.0.0.0", dst="255.255.255.255") / \
                   UDP(sport=68, dport=67) / \
                   BOOTP(chaddr="08:00:27:13:c2:0f", yiaddr=pkt[BOOTP].yiaddr, xid=pkt[BOOTP].xid) / \
                   DHCP(options=[("message-type", "request"), "end"])
    time.sleep(1)
    sendp(dhcp_request)
    print("sent REQUEST")
    # wait for an ack packet from the DHCP server in port 67
    sniff(filter="udp and port 67", count=1, iface="enp0s3")
    print("got ack")
    print("done with DHCP\n")


# -------DNS related code---------------

# go to dns and ask the ip for www.myApp.com
def dns():
    print("to DNS")
    global ip_app
    mac = "08:00:27:13:c2:0f"
    print("sending DNS query to 'www.myApp.com'")

    # Create DNS packet with a query for www.myApp.com
    dns_query = DNS(rd=1, qd=DNSQR(qname="www.myApp.com", qtype=1))

    # Create IP packet with destination DNS server and DNS query
    ip_packet = Ether(src=mac, dst=mac) / IP(src=client_ip, dst=dns_ip) / UDP(dport=53, sport=5300) / dns_query

    # Send packet and capture response
    sendp(ip_packet, iface="enp0s3", verbose=2)
    dns_respond = sniff(filter="udp and port 5300", count=1)
    print("got DNS response")
    ip_app = dns_respond[0][DNSRR][0].rdata
    print("ip of the app: ", ip_app)

    print("done with DNS\n")


# -------APP related code---------------
# rUDP

def app_rUDP():
    global ip_app, client_ip, seq_num, ack, buffer_size
    buffer_size = 16384  # the max len of the window
    server_port = 80
    seq_num = 0
    count = 5
    print("client max window= ", buffer_size)
    # while loop to send the buffer_size again to the app if we didn't get an ack
    while count:
        # create a UDP packet to tell the app the len of the window
        ip = IP(dst=ip_app, src=client_ip)
        udp = UDP(sport=8000, dport=server_port)
        http = "GET / HTTP/4,Host: {},buffer_size: {},seq: {}".format(ip_app, buffer_size, seq_num)
        pkt = ip / udp / http
        send(pkt)
        print("send max window")
        # get ack about the get http4
        print("wait for ack")
        count -= 1
    sniff(filter="udp and port 8000 and src host " + ip_app, count=1, timeout=5)
    get_image()


# get image from app
def get_image():
    global buffer_size, udp_port, client_port_rudp

    # data for opening sockets
    udp_ip = "127.0.0.1"
    addr = '0.0.0.0'  # just till he will get the first chunk of the image

    # Create a UDP socket and bind it to the specified IP address and port
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # ipv4, udp socket
    sock.bind((udp_ip, client_port_rudp))
    sock.setblocking(False)  # socket not blocking for timeout
    time.sleep(4)  # wait for app to get path from server
    count = 0
    # Open a file to write the received chunks to
    with open("received_image.jpg", "wb") as f:
        prev_seq = 0
        # Receive and write each chunk to the file
        while True:
            num = 5  # for timeout
            data = 0
            print("wait to recv")

            # try to get the chunk fot 5 seconds else we send nack to the app
            while num:
                # print("num = ", num)
                try:
                    data, addr = sock.recvfrom(buffer_size)
                except socket.error:
                    # no data available to receive
                    pass
                time.sleep(1)  # timeout
                num -= 1
                if data:
                    seq = (str(data)).split("seq!!!!!")[0]
                    # print("seq=", seq)
                    if seq == "b'final'":
                        break
                    data = data[(len(seq)-2)+len("seq!!!!!"):]
                    seq = seq.replace("seq!!!!!", "").replace("b'", "").replace('b"', "")
                    # if seq == "final'":
                    #     break
                    seq = int(seq)
                    print("got packet seq:", seq)
                    # print("data =", data)
                    if seq == prev_seq:
                        # write data to file
                        f.write(data)
                        prev_seq += 1
                        count = 0
                    else:
                        count += 1
                    break
            # in the last packet, after all the image was send we got a final message
            if data == b'final' or count == 10:
                print("got all the image!")
                break
            # if after 5 seconds we didn't get any data we send nack
            # send the ack/nack
            ack_re = "ack:" + str(prev_seq-1)
            if addr != '0.0.0.0':
                sock.sendto(ack_re.encode(), addr)
                print("send seq: ", prev_seq-1)
                # print("ack_re", ack_re)


    sock.close()

    print("opening image...")
    # open the image
    im = Image.open(r"received_image.jpg")
    im.show()


# TCP
def app_TCP():
    global client_port_tcp, client_ip, ip_app

    # send get req for image
    while True:
        pkt = IP(src=client_ip, dst=ip_app) / TCP(sport=30693, dport=80, seq=0, window=8192, ack=0, flags='A')
        send(pkt)
        print("send get image")
        pkt = sniff(filter="tcp and src host " + ip_app, count=1, timeout=5)
        if pkt:
            print("recv ack")
            break
    # create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # connect the socket to the server's address and port
    server_address = ('127.0.0.1', client_port_tcp)
    print('connecting to {} port {}'.format(*server_address))
    time.sleep(2)
    sock.bind(('127.0.0.1', 30693))
    print("bind")
    sock.connect(server_address)
    print("wait to recv")
    # send an HTTP GET request for the image
    request = b"GET /image HTTP/1.1\r\nHost: www.myApp.com\r\n\r\n"
    sock.sendall(request)

    # receive the response and save it as an image file
    response = b''
    data = 0
    while data == 0:
        time.sleep(5)
        data = sock.recv(44)
        # print("data = ", data)
    while True:
        data = sock.recv(1024)
        print("got packet")
        if not data:
            print("got all the image!")
            break
        response += data

    # write data to file
    with open("received_image.jpg", 'wb+') as f:
        f.write(response)

        # print("response = ", response)
        print("opening image...")
        if response != b'':
            im = Image.open(r"received_image.jpg")
            im.show()
        else:
            print("didn't receive image...")

    # close the socket
    sock.close()
    print("done")


if __name__ == '__main__':
    global client_ip, ip_app

    dhcp()
    if client_ip != "0.0.0.0":
        dns()
        if ip_app != "0.0.0.0":
            # print("now enable packet loss")
            # time.sleep(10)
            ok = True
            # let the user decide protocol and if to exit or again
            while ok:
                els = True  # for exit
                # the user chose protocol
                x = input("Enter U for rUdp or T for TCP: ")
                if x == 'U':
                    print("you chose rUDP!")
                    app_rUDP()
                elif x == 'T':
                    print("you chose TCP!")
                    app_TCP()
                else:
                    print("again please...")
                    els = False
                print("back to main")
                if els:
                    to_exit = input("enter E to exit or C to chose protocol again: ")
                    if to_exit == 'E':
                        ok = False

    print("done")
