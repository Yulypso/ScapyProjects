from scapy.layers.inet import TCP, IP
from scapy.sendrecv import sr
from scapy.volatile import RandNum


def displayPort(portList):
    for a in portList:
        if a.answer[TCP].flags.SA:
            print("[+]", a.answer[TCP].sport, "is open")


def portScan(ip, rangePort):
    """
    Scan des 1024 premiers ports
    flag: S pour envoyer un SYN
    flag: SA pour SYN ACK signifiant que le port est ouvert
    :param rangePort:
    :param ip:
    :return:
    """
    ans, _ = sr(IP(dst=ip) / TCP(sport=RandNum(32000, 33000), dport=rangePort, flags='S'), timeout=3, verbose=0)
    return [a for a in ans]


if __name__ == '__main__':
    displayPort(portScan("10.0.4.39", (1, 1024)))

