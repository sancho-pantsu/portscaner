from struct import pack
from scapy.all import socket, Packet
from scapy.layers.inet import IP, TCP


def view(msg: bytes):
    res = ''
    c = 0
    for i in range(0, len(msg), 2):
        if c > 0 and c % 10 == 0:
            res += '\n'
        if i < len(msg) - 1:
            w = (msg[i] << 8) + msg[i + 1]
        else:
            w = msg[i]
        res += (str(hex(w))[2:]).zfill(4) + ' '
        c += 1

    return res


class TcpPacket:
    tcpHeaderChecksum = 0x0
    seqNo = 0x0
    ackNo = 0x0
    reserved = 0x0
    windowSize = 0x2000
    urgPointer = 0x0
    dataOffset = 0x5
    protocol = 0x6

    ns, flags = 0x0, 0x0
    dataOffsetResFlags = None

    def __init__(self, sourceIp: str, destinationIp: str, sourcePort: int, destinationPort: int, flags: int,
                 data: bytes = b''):
        self.sourceIp = sourceIp
        self.destinationIp = destinationIp
        self.sourcePort = sourcePort
        self.destinationPort = destinationPort
        self.sourceAddress = socket.inet_aton(sourceIp)
        self.destinationAddress = socket.inet_aton(destinationIp)

        self.flags = flags
        self.data = data

        self.calcDataOffsetResFlags()

        self.tcpHeader = b''

    def calcDataOffsetResFlags(self) -> None:
        self.dataOffsetResFlags = (self.dataOffset << 12) \
                                  + (self.reserved << 9) \
                                  + (self.ns << 8) \
                                  + self.flags

    @staticmethod
    def calcChecksum(msg: bytes) -> int:
        s = 0
        for i in range(0, len(msg), 2):
            w = (msg[i] << 8) + msg[i + 1]
            s = s + w
        s = (s >> 16) + (s & 0xffff)
        s = ~s & 0xffff
        return s

    def generateTmpTcpHeader(self) -> bytes:
        return pack("!HHLLHHHH", self.sourcePort, self.destinationPort, self.seqNo, self.ackNo, self.dataOffsetResFlags,
                    self.windowSize, self.tcpHeaderChecksum, self.urgPointer)

    def setTcpHeader(self) -> None:
        tmpTcpHeader = self.generateTmpTcpHeader()
        pseudoHeader = pack("!4s4sBBH", self.sourceAddress, self.destinationAddress, self.tcpHeaderChecksum,
                            self.protocol, len(tmpTcpHeader))
        psTmpTcpHeader = pseudoHeader + tmpTcpHeader
        self.tcpHeader = pack("!HHLLHHHH", self.sourcePort, self.destinationPort, self.seqNo, self.ackNo,
                              self.dataOffsetResFlags, self.windowSize, TcpPacket.calcChecksum(psTmpTcpHeader),
                              self.urgPointer)

    def setData(self, data: bytes) -> None:
        self.data = data

    @property
    def packet(self) -> Packet:
        self.setTcpHeader()
        return IP(dst=self.destinationIp) / TCP(self.tcpHeader + self.data)
