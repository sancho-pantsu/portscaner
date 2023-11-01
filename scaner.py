import time
from datetime import datetime
from scapy.layers.inet import IP, TCP, UDP
import socket

from senders.tcpSenderManual import TcpSenderManual
from senders.tcpSenderScapy import TcpSenderScapy
from senders.udpSender import UdpSender


def getOpenedPort() -> int:
    s = socket.socket()
    try:
        s.bind(("", 0))
    except:
        time.sleep(1)
        s.bind(("", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def getHostIp(dst: str) -> str:
    return IP(dst=dst).src


def tcpGuess(dst: str,
             dport: int,
             timeout: int = 2) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((dst, dport))
    try:
        sock.recv(4096)
    except:
        pass

    # ECHO
    echoData = b'abcdefghijklmnop'
    try:
        sock.send(echoData)
        data = sock.recv(4096)
        if data == echoData:
            sock.close()
            return 'ECHO'
    except:
        pass

    # HTTP
    httpData = b'GET / HTTP/1.1\r\nHost:abc.com\r\n\r\n'
    try:
        sock.send(httpData)
        data = sock.recv(4096)
        if b'HTTP' in data:
            sock.close()
            return 'HTTP'
    except:
        pass

    # DNS
    dnsData = bytes.fromhex('40 58 01 00 00 01 00 00 00 00 '
                            '00 00 04 70 6c 61 79 06 67 6f '
                            '6f 67 6c 65 03 63 6f 6d 00 00 '
                            '01 00 01')
    try:
        sock.send(dnsData)
        data = sock.recv(4096)
        if b'google' in data:
            sock.close()
            return 'DNS'
    except:
        pass

    sock.close()
    return '-'


def tcpScanManual(dst: str,
                  dport: int,
                  timeout: int = 2) -> (bool, int):
    sender = TcpSenderManual(getHostIp(dst), dst, getOpenedPort(), dport, timeout)

    rsp = sender.syn()
    if rsp is not None:
        if rsp.haslayer(TCP) and rsp[TCP].flags == 18:
            sender.rst()
            return True, int(rsp.time / 1000000)
    return False, -1


def tcpScanScapy(dst: str,
                 dport: int,
                 timeout: int = 2) -> (bool, int):
    sender = TcpSenderScapy(getHostIp(dst), dst, getOpenedPort(), dport, timeout)
    rsp = sender.syn()
    if rsp is not None:
        if rsp.haslayer(TCP) and rsp[TCP].flags == 18:
            sender.rst()
            return True, int(rsp.time / 1000000)
    return False, -1


def tcpScanConnect(dst: str,
                   dport: int,
                   timeout: int = 2) -> (bool, int):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        connectingStarted = datetime.now()
        s.connect((dst, dport))
        time = int((datetime.now() - connectingStarted).microseconds / 1000)
        return True, time
    except:
        return False, -1


def udpGuess(dst: str,
             dport: int,
             timeout: int = 2) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    # ECHO
    echoData = b'abcdefghijklmnop'
    try:
        sock.sendto(echoData, (dst, dport))
        data, _ = sock.recvfrom(4096)
        if data == echoData:
            sock.close()
            return 'ECHO'
    except:
        pass

    # DNS
    dnsData = bytes.fromhex('40 58 01 00 00 01 00 00 00 00 '
                            '00 00 04 70 6c 61 79 06 67 6f '
                            '6f 67 6c 65 03 63 6f 6d 00 00 '
                            '01 00 01')
    try:
        sock.sendto(dnsData, (dst, dport))
        data, _ = sock.recvfrom(4096)
        if b'google' in data:
            sock.close()
            return 'DNS'
    except:
        pass

    sock.close()
    return '-'


def udpScan(dst: str,
            dport: int,
            timeout: int = 2,
            retries: int = 0) -> bool:
    sender = UdpSender(getHostIp(dst), dst, getOpenedPort(), dport, timeout)
    rsp = sender.send()
    for _ in range(retries):
        if rsp is not None:
            break
        sender.send()
    if rsp is None or rsp.haslayer(UDP):
        return True
    return False


def scan(protocol: str,
         dst: str,
         dport: int,
         mode: str = 'm',
         timeout: int = 2,
         guess: bool = False) -> (bool, int, str):
    res, time, appProtocol = False, '-', '-'
    if protocol == 'TCP':
        if mode == 'm':
            res, time = tcpScanManual(dst, dport, timeout)
        elif mode == 's':
            res, time = tcpScanScapy(dst, dport, timeout)
        else:
            res, time = tcpScanConnect(dst, dport, timeout)

        if res and guess:
            appProtocol = tcpGuess(dst, dport, timeout)
    else:
        res = udpScan(dst, dport, timeout)

        if res and guess:
            appProtocol = udpGuess(dst, dport, timeout)
    return res, time, appProtocol
