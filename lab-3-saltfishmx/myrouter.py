#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.arp_table={}
        # other initialization stuff here
    def update_table(self,duration):
        for key in list(self.arp_table):
            if time.time()-self.arp_table[key][1]>duration:
                #log_info(f"out of time , now poping {key}--{arp_table[key]} out of arp_table")
                self.arp_table.pop(key)

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        
        if packet.has_header(Arp) == False:
            log_info("Received a non-arp packet")
        else:
            arp = packet.get_header(Arp)
            #itface = self.net.interface_by_ipaddr(arp.targetprotoaddr)
            self.arp_table[arp.senderprotoaddr]=[arp.senderhwaddr,time.time()]
            self.update_table(10)
            log_info(f"now the arp_table looked like:{self.arp_table}")
            for  itface in self.net.interfaces():
                if arp.targetprotoaddr == itface.ipaddr:
                    pket=create_ip_arp_reply(itface.ethaddr,arp.senderhwaddr,arp.targetprotoaddr,arp.senderprotoaddr) #create_ip_arp_reply(senderhwaddr, targethwaddr, senderprotoaddr, targetprotoaddr)
                    self.net.send_packet(ifaceName,pket)
        # TODO: your logic here
            #return 

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
