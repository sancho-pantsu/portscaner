from scapy.packet import Packet
from scapy.sendrecv import sr1

from scaner.tcpPacket import TcpPacket


class TcpSender:
    def __init__(self, src: str, dst: str, sport: int, dport: int, timeout: int = 2):
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport
        self.timeout = timeout

    def syn(self, data: bytes = b'') -> Packet:
        return sr1(TcpPacket(self.src, self.dst, self.sport, self.dport, 0x02, data).packet,
                   timeout=self.timeout, verbose=False)

    def ack(self, data: bytes = b'') -> Packet:
        return sr1(TcpPacket(self.src, self.dst, self.sport, self.dport, 0x10, data).packet,
                   timeout=self.timeout, verbose=False)

    def finAck(self, data: bytes = b'') -> Packet:
        return sr1(TcpPacket(self.src, self.dst, self.sport, self.dport, 0x11, data).packet,
                   timeout=self.timeout, verbose=False)

    def send(self, data: bytes = b'') -> Packet:
        return sr1(TcpPacket(self.src, self.dst, self.sport, self.dport, 0x11, data).packet,
                   timeout=self.timeout, verbose=False)
