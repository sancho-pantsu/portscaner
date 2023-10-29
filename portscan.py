import argparse
from scaner import *

import logging
logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)


def parsePorts(data: str, tcpPrts: list, udpPrts) -> None:
    protocols, ports_data = data.split('/')
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


def printTabs(verbose: bool = False, guess: bool = False) -> None:
    res = 'PROTOCOL\tPORT\t'
    if verbose:
        res += 'TIME,ms\t'
    if guess:
        res += 'APP PROTO\t'
    print(res)


args, dst, tcpPorts, udpPorts = read()
printTabs(args['verbose'], args['guess'])
found = False

for port in tcpPorts:
    found = found or tcpScan(dst, port, args['timeout'], args['verbose'], args['guess'])

for port in udpPorts:
    found = found or udpScan(dst, port, args['timeout'], args['verbose'], args['guess'])

if not found:
    print('Not found any opened ports((')
