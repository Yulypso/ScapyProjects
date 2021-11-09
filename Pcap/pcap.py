from scapy.layers.inet import IP
from scapy.utils import PcapReader, PcapWriter


def pcapFilterByIp(inputFile, ip):
    """
    :param inputFile: input pcap filename to filter
    :param ip: ip to filter with
    :return: None
    """
    outputFilename = inputFile.replace('.pcap', '') + "-[filtered-" + ip + "].pcap"
    with PcapReader(inputFile) as pcapReader, PcapWriter(outputFilename, append=True) as pcapWriter:
        for p in pcapReader:
            if p[IP].dst == ip or p[IP].src == ip:
                pcapWriter.write(p)
    print("[+] " + outputFilename)


if __name__ == '__main__':
    pcapFilterByIp("./2015-09-18-Nuclear-EK-traffic.pcap", "178.218.166.171")
