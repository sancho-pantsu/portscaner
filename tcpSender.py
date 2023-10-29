from scapy.packet import Packet


class TcpSender:
    def send(self, flags: int, data: bytes, timeout: int, verbose: bool) -> Packet:
        pass

    def syn(self, data: bytes = b'', timeout: int = None, verbose: bool = None) -> Packet:
        pass

    def ack(self, data: bytes = b'', timeout: int = None, verbose: bool = None) -> Packet:
        pass

    def finAck(self, data: bytes = b'', timeout: int = None, verbose: bool = None) -> Packet:
        pass

    def rstAck(self, data: bytes = b'', timeout: int = None, verbose: bool = None) -> Packet:
        pass

    def sendData(self, data: bytes = b'', timeout: int = None, verbose: bool = None) -> Packet:
        pass
