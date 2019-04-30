#!/usr/bin/python3

# print the banner if there is one
import os
if os.path.isfile('banner.txt'):
    print(open('banner.txt', 'r', encoding='utf-8').read())
print('[*] Initializing...')

import re
from scapy.all import *
from argparse import ArgumentParser
from colorama import init, Fore, Style

# init colorama and default password regex
default_regex = r'p(ass(?:word|w|wd|)|w|wd)='
init(autoreset=True)  # colorama init

def process_args():
    '''
    parse arguments
    '''
    parser = ArgumentParser(prog='Password Sniffer', description='A simple password sniffer available on Windows.')
    parser.add_argument('-c', '--count', default=0, help='number of packets to capture. 0 means infinity.')
    parser.add_argument('-p', '--pcap', help='PCAP file to read packets from, instead of sniffing them.')
    parser.add_argument('-f', '--filter', dest='filter', help='BPF filter to apply.')
    parser.add_argument('-r', '--regex', default=default_regex, help='regex expression as password pattern.')
    parser.add_argument('-i', '--iface', default=conf.iface, help='interface or list of interfaces.')
    return parser.parse_args()
    
def pass_to_parse(pkt, pattern):
    '''
    parse the packet and return content containing password information
    '''
    try:
        printable = pkt.load.decode('ascii', 'ignore')
    except AttributeError:
        # Here comes a packet without payload
        return None

    hit = pattern.search(printable)
    if hit:
        keyword = hit.group()
        lcontext, rcontext = printable.split(keyword)
        load = lcontext + Fore.RED + Style.BRIGHT + keyword + Style.RESET_ALL + rcontext + '\n'
        summary = Fore.GREEN + pkt.summary() + Fore.RESET + '\n'
        return summary + load
    else:
        return None

def main(args):
    print('[*] Using interface:', args.iface)
    print('[*] press ctrl-C to stop')
    pattern = re.compile(args.regex, re.I)
    sniff(filter = args.filter,
            count = args.count, 
            iface = args.iface,
            offline = args.pcap,
            prn = lambda x: pass_to_parse(x, pattern)
            )

if __name__ == '__main__':
    main(process_args())
