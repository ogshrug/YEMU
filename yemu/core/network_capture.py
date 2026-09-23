import logging

# scapy warns about a missing libpcap provider on import; reading capture files doesn't need one
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.layers.dns import DNS
    from scapy.layers.inet import IP
    from scapy.utils import rdpcap

    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False


class NetworkCapture:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def analyze_pcap(self, pcap_path):
        iocs = set()
        if not HAVE_SCAPY:
            self.logger.warning("Scapy not found. PCAP analysis disabled.")
            return []

        try:
            packets = rdpcap(pcap_path)
            for pkt in packets:
                if pkt.haslayer(IP):
                    iocs.add(("ip", pkt[IP].dst))
                dns = pkt.getlayer(DNS)
                if dns is not None and dns.qr == 0 and dns.qd is not None:
                    iocs.add(("domain", dns.qd.qname.decode('utf-8').rstrip('.')))
        except Exception as e:
            self.logger.error(f"PCAP analysis failed: {e}")

        return list(iocs)
