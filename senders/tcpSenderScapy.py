from scapy.layers.inet import IP, TCP
from scapy.packet import Packet
from scapy.sendrecv import sr1

from tcpSender import TcpSender


class TcpSenderScapy(TcpSender):
    def __init__(self, src: str, dst: str, sport: int, dport: int, timeout: int = 2, verbose: bool = False):
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport
        self.timeout = timeout
        self.verbose = verbose

    def send(self, flags: str, data: bytes, timeout: int, verbose: bool) -> Packet:
        pkt = IP(dst=self.dst)/TCP(sport=self.sport, dport=self.dport, flags=flags)
        if data:
            pkt = pkt / data
        return sr1(pkt,
                   timeout=self.timeout if timeout is None else timeout,
                   verbose=self.verbose if verbose is None else verbose)

    def syn(self, data: bytes = b'', timeout: int = None, verbose: bool = None) -> Packet:
        return self.send('S', data, timeout, verbose)

    def ack(self, data: bytes = b'', timeout: int = None, verbose: bool = None) -> Packet:
        return self.send('A', data, timeout, verbose)

    def finAck(self, data: bytes = b'', timeout: int = None, verbose: bool = None) -> Packet:
        return self.send('FA', data, timeout, verbose)

    def rstAck(self, data: bytes = b'', timeout: int = None, verbose: bool = None) -> Packet:
        return self.send('RA', data, timeout, verbose)

    def sendData(self, data: bytes = b'', timeout: int = None, verbose: bool = None) -> Packet:
        return self.send('PA', data, timeout, verbose)
