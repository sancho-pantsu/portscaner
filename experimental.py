from senders.tcpSenderManual import TcpSenderManual
from scaner import getHostIp, getOpenedPort
from senders.tcpSenderScapy import TcpSenderScapy

mode = input('enter mode: (m)anual or (s)capy: ')

dst = '216.58.209.174'
dport = 80
if mode == 'm':
    sender = TcpSenderManual(getHostIp(dst), dst, getOpenedPort(), dport, timeout=5)
else:
    sender = TcpSenderScapy(getHostIp(dst), dst, getOpenedPort(), dport, timeout=5)

sender.syn()
