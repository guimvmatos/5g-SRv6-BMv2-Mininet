#!/usr/bin/env python
import sys
import struct
import os
import argparse
import socket
import random
import argparse
import time

from scapy.all import sniff, send, sendp, hexdump, get_if_list, get_if_hwaddr, hexdump, sr1, sr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, IPv6, TCP, UDP, Raw, Ether
from scapy.layers.inet import _IPOption_HDR

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]
                                
def handle_pkt(pkt):
    #if UDP in pkt and pkt[UDP].dport == 2152:
    #if UDP in pkt:
    print "got a packet"
    pkt.show2()
    #hexdump(pkt) 

    print "===================================ENVIANDO PACOTE ALTERADO============================="
    time.sleep(5)
    pkt2 = pkt
    temp = pkt[Ether].src
    pkt2[Ether].src = pkt2[Ether].dst
    pkt2[Ether].dst = temp
    
    pkt2[Raw] = (b"host3")
    pkt2.show2()
    sendp(pkt2, loop=0, count=1)
    #sr1(sendp(pkt2, loop=1, verbose = False))
    main()
    
    


    


def main():
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))
    print "teste"

if __name__ == '__main__':
    main()
