from scapy.packet import Packet
from scapy.sendrecv import sr1

from packets.tcpPacket import TcpPacket
from . import tcpSender


class TcpSenderManual(tcpSender.TcpSender):
    def __init__(self, src: str, dst: str, sport: int, dport: int, timeout: int = 2, verbose: bool = False):
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport
        self.timeout = timeout
        self.verbose = verbose

    def send(self, flags: int, data: bytes, timeout: int, verbose: bool) -> Packet:
        return sr1(TcpPacket(self.src, self.dst, self.sport, self.dport, flags, data).packet,
                   timeout=self.timeout if timeout is None else timeout,
                   verbose=self.verbose if verbose is None else verbose)

    def syn(self, data: bytes = b'', timeout: int = None, verbose: bool = None) -> Packet:
        return self.send(0x02, data, timeout, verbose)

    def ack(self, data: bytes = b'', timeout: int = None, verbose: bool = None) -> Packet:
        return self.send(0x10, data, timeout, verbose)

    def finAck(self, data: bytes = b'', timeout: int = None, verbose: bool = None) -> Packet:
        return self.send(0x11, data, timeout, verbose)

    def rst(self, data: bytes = b'', timeout: int = None, verbose: bool = None) -> Packet:
        return self.send(0x04, data, timeout, verbose)

    def sendData(self, data: bytes = b'', timeout: int = None, verbose: bool = None) -> Packet:
        return self.send(0x18, data, timeout, verbose)
