import argparse
from scaner import *

import logging

logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)

allowedProtocols = {'tcp', 'udp'}


def parsePorts(data: str, tcpPrts: list, udpPrts) -> None:
    if '/' not in data:
        raise Exception('Incorrect format of port ranges')
    protocols, ports_data = data.split('/')
    protocols = protocols.lower()
    if not set(protocols.split('|')).issubset(allowedProtocols):
        raise Exception('Only TCP or UDP is allowed to scan')
    ranges = ports_data.split(',')
    for i in ranges:
        if '-' not in i:
            ports = [int(i)]
        else:
            a, b = map(int, i.split('-'))
            ports = list(range(a, b + 1))
        if 'tcp' in protocols:
            tcpPrts += ports
        if 'udp' in protocols:
            udpPrts += ports


def read():
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout", type=int, default=2)
    parser.add_argument("-m", "--mode", type=str, choices=['m', 's', 'c'], default='m')
    parser.add_argument("-j", "--num-threads", type=int, default=1)
    parser.add_argument("-v", "--verbose", action="store_true", default=False)
    parser.add_argument("-g", "--guess", action="store_true", default=False)
    parser.add_argument("dst", type=str)
    parser.add_argument("ports", type=str, nargs='+')
    args = vars(parser.parse_args())

    tcpPrts, udpPrts = [], []
    unparsed_port_ranges = args["ports"]
    port_ranges = []
    i = 0
    try:
        while i < len(unparsed_port_ranges):
            if '/' in unparsed_port_ranges[i]:
                port_ranges += [unparsed_port_ranges[i]]
            else:
                port_ranges += [f'{unparsed_port_ranges[i]}|{unparsed_port_ranges[i + 1]}']
                i += 1
            i += 1
    except:
        raise Exception("Incorrect port ranges")

    for i in port_ranges:
        parsePorts(i, tcpPrts, udpPrts)

    return args, args["dst"], tcpPrts, udpPrts


def out(protocol: str,
        dport: int,
        verbose: bool = False,
        time: str = '-',
        guess: bool = False,
        appProtocol: str = None):
    res = f'{protocol}     \t{dport}\t'
    if verbose:
        res += f'{time}\t'
    if guess:
        res += f'{appProtocol}\t'
    print(res)


def printTabs(mode: str, verbose: bool = False, guess: bool = False) -> None:
    d = {'m': 'manual', 's': 'scapy', 'c': 'full connection'}
    print(f'Scanning in {d[mode]} mode')
    res = 'PROTOCOL\tPORT\t'
    if verbose:
        res += 'TIME,ms\t'
    if guess:
        res += 'APP PROTO\t'
    print(res)


args, dst, tcpPorts, udpPorts = read()
printTabs(args['mode'], args['verbose'], args['guess'])
found = False

for dport in tcpPorts:
    res, time, appProtocol = scan('TCP', dst, dport, mode=args['mode'],
                                  timeout=args['timeout'], guess=args['guess'])
    found = found or res
    if res:
        out('TCP', dport, args['verbose'], time, args['guess'], appProtocol)

for dport in udpPorts:
    res, time, appProtocol = scan('UDP', dst, dport, mode=args['mode'],
                                  timeout=args['timeout'], guess=args['guess'])
    found = found or res
    if res:
        out('UDP', dport, args['verbose'], guess=args['guess'], appProtocol=appProtocol)

if not found:
    print('Not found any opened ports((')
