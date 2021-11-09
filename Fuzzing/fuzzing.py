from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.ntp import NTP
from scapy.packet import fuzz, Raw
from scapy.sendrecv import send, sr
from scapy.volatile import CorruptedBytes, CorruptedBits


def introDestructiveFuzzing():
    """
    Corruption d'un paquet fuzz()
    :return:
    """
    payload = "captured payload"
    print(f"payload: {payload}")
    corruptedPayload = CorruptedBytes(payload)
    print(f"corruptedPayload: {corruptedPayload}")
    corruptedPayload = CorruptedBits(payload)
    print(f"corruptedPayload: {corruptedPayload}")
    send(IP(dst="8.8.8.8") / UDP() / Raw(load=corruptedPayload), loop=1)


def introCreativeFuzzing():
    """
    Constructive
    Création d'un paquet fuzz()
    fuzz() Transforme un paquet avec des valeurs randoms cohérentes pour ne pas violer la norme
    :return:
    """
    f = IP(dst="8.8.8.8") / fuzz(UDP() / NTP(version=4))
    f.show2()


if __name__ == '__main__':
    introCreativeFuzzing()
    introDestructiveFuzzing()
