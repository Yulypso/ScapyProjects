from scapy.layers.inet import TCP, IP
from scapy.sendrecv import sr


def portScan(ip):
    ans, _ = sr(IP(dst=ip) / TCP(dport=(1, 1025), flags='S'), verbose=0)
    for a in ans:
        if a.answer[TCP].flags.SA:
            print("[+] ", a.answer[TCP].sport, "is open")


if __name__ == '__main__':
    portScan("10.0.4.254")
