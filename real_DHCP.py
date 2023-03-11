from scapy.all import*
import time

from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

global dhcp_ip, end_ip, LIST_OF_IP
dhcp_ip = "10.0.0.17"
end_ip = 17
LIST_OF_IP = ["10.0.0.17", "10.0.0.18", "10.0.0.10"]

def dhcp_offer(pkt):
    global end_ip, LIST_OF_IP
    if DHCP in pkt and pkt[DHCP].options[0][1] == 1:
        print("got DISCOVER")
        client_ip = "10.0.0." + str(end_ip)
        while client_ip in LIST_OF_IP:
            print("ip: ", client_ip, "is already in use")
            end_ip += 1
            if end_ip > 254:
                print("DONT HAVE ANYMORE IP'S.")
                client_ip = "0.0.0.0" # if there is no more available ip, the ip of the client will be 0.0.0.0
                break
            client_ip = "10.0.0." + str(end_ip)
        dhcp_offer = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                 IP(src=dhcp_ip, dst="255.255.255.255") / \
                 UDP(sport=67, dport=68) / \
                 BOOTP(op=2, yiaddr=client_ip, siaddr=dhcp_ip, giaddr="0.0.0.0", xid=pkt[BOOTP].xid) / \
                 DHCP(options=[("message-type", "offer"),
                    ("subnet_mask", "255.255.255.0"),
                    ("router", "10.0.0.10"),
                    ("name_server", "10.0.0.18"),
                    ("lease_time", 3600), "end"])

        time.sleep(1)
        sendp(dhcp_offer, iface="enp0s3")
        print("send OFFER")
        sniff(filter="udp and port 68", prn=dhcp_ack, count=1, iface="enp0s3")

def dhcp_ack(pkt):
    global end_ip, LIST_OF_IP

    if DHCP in pkt and pkt[DHCP].options[0][1] == 3:  # Check if it's a DHCP REQUEST packet
        print("got REQUEST")
        LIST_OF_IP.append(pkt[BOOTP].yiaddr)
        print("IP appreved, DHCP append the IP to list")
        print(LIST_OF_IP)
        dhcp_ack = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                   IP(src=dhcp_ip, dst="255.255.255.255") / \
                   UDP(sport=67, dport=68) / \
                   BOOTP(op=2, yiaddr=pkt[BOOTP].yiaddr, siaddr=pkt[BOOTP].siaddr, giaddr="0.0.0.0", xid=pkt[BOOTP].xid) / \
                   DHCP(options=[("message-type", "ack"),
                                 ("subnet_mask", "255.255.255.0"),
                                 ("router", "10.0.0.18"),
                                 ("lease_time", 3600), "end"])
        time.sleep(1)
        sendp(dhcp_ack, iface="enp0s3")
        print("send ACK")
        print("done with client")


if __name__ == '__main__':
    print("DHCP on")
    sniff(filter="udp and port 68", prn=dhcp_offer, iface="enp0s3")