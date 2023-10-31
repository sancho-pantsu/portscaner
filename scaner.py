from datetime import datetime
from scapy.layers.inet import IP, TCP, UDP
import socket as skt

from scapy.sendrecv import sr1

from senders.tcpSender import TcpSender
from senders.tcpSenderManual import TcpSenderManual


def getOpenedPort() -> int:
    s = skt.socket()
    s.bind(("", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def getHostIp(dst: str) -> str:
    return IP(dst=dst).src


def out(protocol: str,
        port: int,
        verbose: bool = False,
        time: str = '-',
        guess: bool = False,
        appProtocol: str = None):
    res = f'{protocol}     \t{port}\t'
    if protocol == 'TCP':
        if verbose:
            res += f'{time}\t'
    elif protocol == 'UDP':
        pass
    if guess:
        res += f'{appProtocol}\t'
    print(res)


def tcpGuess(sender: TcpSender) -> str:
    data = 'GET / HTTP/1.1\r\nHost: abc.def\r\n\r\n'
    rsp = sender.sendData(bytes(data, 'utf-8'), verbose=True)
    if rsp is None:
        return '-'

    return rsp[TCP].payload


def tcpScan(dst: str,
            dport: int,
            timeout: int = 2,
            verbose: bool = False,
            guess: bool = False) -> bool:
    sender = TcpSenderManual(getHostIp(dst), dst, getOpenedPort(), dport, timeout)
    opened = False

    rsp = sender.syn()
    if rsp is not None:
        if rsp.haslayer(TCP) and rsp[TCP].flags == 18:
            opened = True

            if guess:
                sender.ack()

                out("TCP", dport, verbose=verbose, time=str(int(rsp.time / 1000)),
                    guess=guess, appProtocol=tcpGuess(sender))

                sender.finAck()
                sender.ack()
            else:
                out("TCP", dport, verbose=verbose, time=str(int(rsp.time / 1000)), guess=guess, appProtocol=None)
                sender.rstAck()
    return opened


def tcpScanScapy(dst: str,
                 port: int,
                 timeout: int = 2,
                 verbose: bool = False,
                 guess: bool = False) -> bool:
    pkt = IP(dst=dst) / TCP(sport=getOpenedPort(), dport=port)
    rsp = sr1(pkt, timeout=timeout, verbose=False)
    opened = False
    if rsp is not None:
        if rsp.haslayer(TCP) and rsp[TCP].flags == 0x12:
            out("TCP", port, verbose=verbose, time=str(int(rsp.time / 1000)), guess=guess, appProtocol=None)
            opened = True
    return opened


def tcpScanConnect(dst: str,
                   port: int,
                   timeout: int = 2,
                   verbose: bool = False,
                   guess: bool = False) -> bool:
    s = skt.socket()
    s.settimeout(timeout)
    opened = False
    try:
        connectingStarted = datetime.now()
        s.connect((dst, port))
        time = int((datetime.now() - connectingStarted).microseconds / 1000)
        out("TCP", port, verbose, str(time), guess, None)
        opened = True
    except:
        pass
    return opened


def udpScan(dst: str,
            port: int,
            timeout: int = 2,
            verbose: bool = False,
            guess: bool = False) -> bool:
    pkt = IP(dst=dst) / TCP(sport=getOpenedPort(), dport=port)
    rsp = sr1(pkt, timeout=timeout, verbose=False)
    if rsp is None or rsp.haslayer(UDP):
        out('UDP', port, verbose=verbose, guess=guess, appProtocol=None)
        return True
    return False


if __name__ == '__main__':
    tcpScan('216.58.209.174', 80, guess=True)
