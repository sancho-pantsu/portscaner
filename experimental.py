from tcpSenderManual import TcpSenderManual
from scaner import getHostIp, getOpenedPort


dst = '216.58.209.174'
dport = 80
sender = TcpSenderManual(getHostIp(dst), dst, getOpenedPort(), dport, timeout=5)

sender.syn()
