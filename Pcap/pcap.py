from scapy.layers.inet import IP
from scapy.utils import PcapReader, PcapWriter


def pcapFilterByIp(inputFile, ip):
    """
    :param inputFile: input pcap filename to filter
    :param ip: ip to filter with
    :return: None
    """
    pcapReader = PcapReader(inputFile)
    outputfilename = inputFile.replace('.pcap', '') + "-[filtered-" + ip + "].pcap"
    pcapWriter = PcapWriter(outputfilename, append=True)
    for p in pcapReader:
        if p[IP].dst == ip or p[IP].src == ip:
            pcapWriter.write(p)
    print("[+] " + outputfilename)


if __name__ == '__main__':
    pcapFilterByIp("./2015-09-18-Nuclear-EK-traffic.pcap", "178.218.166.171")
