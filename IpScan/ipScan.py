import random

from scapy.base_classes import Net
from scapy.data import ETHER_BROADCAST
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp


def displayIp(ipList):
    for a in sorted(ipList, key=lambda x: [x.split('.') for x in ipList]):
        print("[+]", a.answer.psrc, "is UP and Mac@ is", a.answer.hwsrc)


def ipScan(networkIp):
    """
    Scan ip on the network (ARP scan)
    :return: liste des adresses IP UP
    """
    random.shuffle(ipList := list(Net(networkIp)))
    ans, _ = srp(Ether(dst=ETHER_BROADCAST) / ARP(op=1, pdst=ipList), timeout=3, verbose=0)
    return [a for a in ans]


if __name__ == '__main__':
    displayIp(ipScan("10.0.4.0/24"))
