#!/usr/bin/env python
import sys
import struct
import os
import argparse
import socket
import random
import argparse
import time

from scapy.all import sniff, send, sendp, hexdump, get_if_list, get_if_hwaddr, hexdump, sr1,sr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, IPv6, TCP, UDP, Raw, Ether,IPv6ExtHdrRouting
from scapy.layers.inet import _IPOption_HDR
from scapy import all
from gpt2 import *

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
    #new implementation
    time.sleep(5)
    if pkt.segleft >= 0:
        new =  Ether(src=pkt[Ether].dst, dst=pkt[Ether].src);
        
        
        extension = IPv6ExtHdrRouting();
        extension.segleft = pkt.segleft-1;
        extension.addresses = pkt.addresses;
        if extension.segleft == 2:
            new = new / IPv6(dst = extension.addresses[2], src="2001:0DB8:AC10:FE01:0000:0000:0000:0002") / extension / UDP (sport=64515, dport=2152 ) / GTP_U_Header(TEID=32)/ IPv6(dst="2001:0DB8:AC10:FE01:0000:0000:0000:0001" , src="2001:0DB8:AC10:FE01:0000:0000:0000:0006") / "host2";
        if extension.segleft == 1:
            new = new / IPv6(dst = extension.addresses[1], src="2001:0DB8:AC10:FE01:0000:0000:0000:0002") / extension / UDP (sport=64515, dport=2152 ) / GTP_U_Header(TEID=32)/ IPv6(dst="2001:0DB8:AC10:FE01:0000:0000:0000:0001" , src="2001:0DB8:AC10:FE01:0000:0000:0000:0006") / "host2";
        if extension.segleft == 0:
            new = new / IPv6(dst = extension.addresses[0], src="2001:0DB8:AC10:FE01:0000:0000:0000:0002") / extension / UDP (sport=64515, dport=2152 ) / GTP_U_Header(TEID=32)/ IPv6(dst="2001:0DB8:AC10:FE01:0000:0000:0000:0001" , src="2001:0DB8:AC10:FE01:0000:0000:0000:0006") / "host2";    
    
    new.show2()
    sendp(new, loop=0, count=1)
    #end of new implementation

    #old implementation
    #time.sleep(5)
    #pkt2 = pkt
    #temp = pkt[Ether].src
    #pkt2[Ether].src = pkt2[Ether].dst
    #pkt2[Ether].dst = temp
    #pkt2.segleft = pkt2.segleft - 1
    #if pkt2.segleft == 1:
    #    pkt2[IPv6].dst = pkt2.addresses[1];
    #if pkt2.segleft == 0:
    #    pkt2[IPv6].dst = pkt2.addresses[0];
    #pkt2[Raw] = (b"host2")
    #pkt2.show2() ja estava comentado
    #sendp(pkt2, loop=0, count=1)
    #sr1(sendp(pkt2, loop=1, verbose = False)) ja estava comentado
    #end of old implementation
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
