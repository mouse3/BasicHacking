import os 
os.system("sudo iptables -I FORWARD -j NFQUEUE --queue-num 0")
os.system("sudo apt-get install build-essential python-dev libnetfilter-queue-dev")
os.system("pip install netfilterqueue")
os.system("pip install SpyWare")
os.system("pip3 install mvt")



