from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether
from scapy.packet import Padding
from scapy.sendrecv import sendp


def level0(src, dst, mac, myId):
    """envoyer un paquet ICMP de type echo request avec dans le payload votre nom et votre prenom"""
    payload = b"KHAMPHOUSONE Thierry"

    sendp(Ether(dst=mac) /
          IP(id=myId, src=src, dst=dst) /
          ICMP() /
          payload)


def level1(src, dst, mac, myId):
    """Envoyer un paquet ICMP de type echo reply un payload et un padding correspondant au payload a l'envers"""
    payload = b"le cafe est tres bon"
    payloadReverse = payload[::-1]

    sendp(Ether(dst=mac) /
          IP(id=myId, src=src, dst=dst) /
          ICMP(type="echo-reply") /
          payload /
          Padding(load=payloadReverse))


def level2(src, dst, mac, myId):

    payload = b""

    sendp(Ether(dst=mac) /
          IP(id=myId, src=src, dst=dst))


if __name__ == '__main__':
    SRC = "1.2.3.4"
    DST = "5.6.7.8"
    MAC = "00:5c:a4:75:ca:47"
    ID = 0x3500

    #level0(SRC, DST, MAC, ID)
    #level1(SRC, DST, MAC, ID)
    level2(SRC, DST, MAC, ID)
