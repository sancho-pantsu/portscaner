from abc import abstractmethod
from scapy.packet import Packet


class TcpSender:
    @abstractmethod
    def send(self, flags: int, data: bytes, timeout: int, verbose: bool) -> Packet:
        pass

    @abstractmethod
    def syn(self, data: bytes = b'', timeout: int = None, verbose: bool = None) -> Packet:
        pass

    @abstractmethod
    def ack(self, data: bytes = b'', timeout: int = None, verbose: bool = None) -> Packet:
        pass

    @abstractmethod
    def finAck(self, data: bytes = b'', timeout: int = None, verbose: bool = None) -> Packet:
        pass

    @abstractmethod
    def rstAck(self, data: bytes = b'', timeout: int = None, verbose: bool = None) -> Packet:
        pass

    @abstractmethod
    def sendData(self, data: bytes = b'', timeout: int = None, verbose: bool = None) -> Packet:
        pass
