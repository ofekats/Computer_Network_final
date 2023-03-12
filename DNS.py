from scapy.all import *
import time
import socket

global IP_DNS, domain_dict
IP_DNS = "10.0.0.18"
domain_dict = {"www.myApp.com": "10.0.2.50"}


def check_domain_to_ip(domain):
    global IP_DNS, domain_dict

    print("domain:", domain)
    if domain in domain_dict:
        print("DNS dict= ", domain_dict)
        print("domain in dict!, IP- ", domain_dict[domain])
        return domain_dict[domain]
    else:
        try:
            print("domain not in dict... sends query to check the IP")
            domain_ip = socket.gethostbyname(domain)
            print("got response, ip-", domain_ip)
            print("enter domain to DNS dict")
            domain_dict[domain] = domain_ip
            return domain_ip
        except socket.gaierror:
            print("Invalid domain name: ", domain)
            return "0.0.0.0"


def handle_dns_request(pkt):
    # Check if packet is a DNS request
    if pkt.haslayer(DNSQR) and pkt.getlayer(UDP).dport == 53 and pkt[IP].dst == IP_DNS:

        # Extract DNS query information
        dns_query = pkt.getlayer(DNSQR)
        qname = dns_query.qname
        qtype = dns_query.qtype
        qclass = dns_query.qclass
        domain = qname.decode('utf-8')[:-1]
        ip = check_domain_to_ip(domain)
        print("Received DNS query for ", domain)
        print(ip)
        # Craft and send DNS response
        dns_response = DNS(id=pkt[DNS].id, qr=1, aa=1, rd=0, qdcount=1, ancount=1, nscount=0, arcount=0,
                           qd=DNSQR(qname=qname, qtype=qtype, qclass=qclass),
                           an=DNSRR(rrname=qname, type=qtype, rclass=qclass, ttl=3600, rdata=ip))

        ip_packet = Ether(dst=pkt[Ether].src, src=pkt[Ether].dst) / IP(dst=pkt[IP].src, src=IP_DNS) / UDP(dport=pkt[UDP].sport, sport=53) / dns_response
        time.sleep(2)
        sendp(ip_packet, iface="enp0s3")
        print("send DNS response")
        print("done with query")


if __name__ == '__main__':
    print("listening to DNS request...")
    # Start sniffing for DNS requests
    sniff(filter="udp and port 53 and not src host " + IP_DNS, prn=handle_dns_request)