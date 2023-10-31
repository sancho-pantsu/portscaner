from scapy.layers.inet import IP, UDP
from scapy.packet import Packet
from scapy.sendrecv import sr1


class UdpSender:
    def __init__(self, src: str, dst: str, sport: int, dport: int, timeout: int = 2, verbose: bool = False):
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport
        self.timeout = timeout
        self.verbose = verbose

    def send(self, data: bytes = b'', timeout: int = 2, verbose: bool = False) -> Packet:
        pkt = IP(dst=self.dst) / UDP(sport=self.sport, dport=self.dport)
        if data:
            pkt = pkt / data
        return sr1(pkt,
                   timeout=self.timeout if timeout is None else timeout,
                   verbose=self.verbose if verbose is None else verbose)
