import random

from scapy.base_classes import Net
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp


def displayIp(ipList):
    for a in ipList:
        print("[+]", a.answer.psrc, "is UP and Mac@ is", a.answer.hwsrc)


def ipScan(networkIp):
    """
    Scan ip on the network (ARP scan)
    :return: liste des adresses IP UP
    """
    ipList = list(Net(networkIp))
    random.shuffle(ipList)
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=ipList), timeout=3, verbose=0)
    return [a for a in ans]


if __name__ == '__main__':
    displayIp(ipScan("10.0.4.0/24"))
