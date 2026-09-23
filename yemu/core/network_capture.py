import logging

try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS
except ImportError:
    rdpcap = None

class NetworkCapture:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def analyze_pcap(self, pcap_path):
        iocs = set()
        if not rdpcap:
            self.logger.warning("Scapy not found. PCAP analysis disabled.")
            return []

        try:
            packets = rdpcap(pcap_path)
            for pkt in packets:
                if pkt.haslayer(IP):
                    iocs.add(("ip", pkt[IP].dst))
                if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
                    qname = pkt.getlayer(DNS).qd.qname.decode('utf-8').rstrip('.')
                    iocs.add(("domain", qname))
        except Exception as e:
            self.logger.error(f"PCAP analysis failed: {e}")

        return list(iocs)
