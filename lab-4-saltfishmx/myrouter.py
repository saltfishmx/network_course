#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *


class ippacketinqueue():
    # a series of ippacket with same ipaddress
    def __init__(self, ippacket, timestamp, retrynum, arprequest, intf):
        self.timestamp = timestamp
        self.ippacket = ippacket
        self.retrynum=retrynum
        self.arprequest=arprequest
        self.intf=intf


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.arp_table = {}
        self.forwarding_table = []
        self.set_forwardingtable()
        self.ipv4packetqueue = {}
        # other initialization stuff here

    def checkqueue(self, duration=1):
        for key in list(self.ipv4packetqueue):
            flag =time.time()-self.ipv4packetqueue[key].timestamp > duration
            if flag == True:
                if(self.ipv4packetqueue[key].retrynum >= 5):
                    self.ipv4packetqueue.pop(key)
                else:
                    arprequest = self.ipv4packetqueue[key].arprequest
                    intf = self.ipv4packetqueue[key].intf
                    self.net.send_packet(intf, arprequest)
                    self.ipv4packetqueue[key].timestamp = time.time()
                    self.ipv4packetqueue[key].retrynum += 1

    def update_table(self, duration):
        for key in list(self.arp_table):
            if time.time()-self.arp_table[key][1] > duration:
                #log_info(f"out of time , now poping {key}--{arp_table[key]} out of arp_table")
                self.arp_table.pop(key)

    def set_forwardingtable(self):
        for itface in self.net.interfaces():
            self.forwarding_table.append([
                itface.ipaddr, itface.netmask, "0.0.0.0", itface.name])
        with open("forwarding_table.txt", "r") as f:
            for line in f:
                substr = line.split()
                self.forwarding_table.append([
                    substr[0], substr[1], substr[2], substr[3]])

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv

        if packet.has_header(Arp) == True:
            arp = packet.get_header(Arp)
            self.arp_table[arp.senderprotoaddr] = [
                arp.senderhwaddr, time.time()]
            self.update_table(10)
            if arp.operation == 1:  # arp request
                for itface in self.net.interfaces():
                    if arp.targetprotoaddr == itface.ipaddr:
                        pket = create_ip_arp_reply(
                            itface.ethaddr, arp.senderhwaddr, arp.targetprotoaddr, arp.senderprotoaddr)
                        self.net.send_packet(ifaceName, pket)
            elif arp.operation == 2:
                ip = arp.senderprotoaddr
                if ip in self.ipv4packetqueue:
                    for pcket in self.ipv4packetqueue[ip].ippacket:
                        e = pcket.get_header(Ethernet)
                        e.dst = arp.senderhwaddr
                        e.src = arp.targethwaddr
                        sendpkt = e + \
                            pcket.get_header(IPv4) + pcket.get_header(ICMP)
                        self.net.send_packet(ifaceName, sendpkt)
                    self.ipv4packetqueue.pop(ip)

        elif packet.has_header(IPv4) == True:
            ipv4 = packet.get_header(IPv4)
            ipv4.ttl -= 1
            # not for router itself
            if ipv4.dst not in [itface.ipaddr for itface in self.net.interfaces()]:
                pos = 0
                maxnum = 0
                i = 0
                find = False
                for entry in self.forwarding_table:
                    prefixnet = IPv4Network(str(entry[0])+"/"+str(entry[1]),False)
                    destaddr=  IPv4Address(ipv4.dst)
                    matches = destaddr in prefixnet
                    if matches == True :
                        if prefixnet.prefixlen > maxnum:
                            maxnum = prefixnet.prefixlen
                            pos = i
                            find = True  # pos indicates the entry which has longest match ,can get ipaddress via it
                    i += 1
                if find == True:  # find == False means no match ,will be droped
                    nexthopip = self.forwarding_table[pos][2]
                    if nexthopip == "0.0.0.0":
                        nexthopip=ipv4.dst                           
                    if nexthopip in self.arp_table:
                        e = packet.get_header(Ethernet)
                        intf = self.forwarding_table[pos][3]
                        e.src = self.net.interface_by_name(intf).ethaddr
                        e.dst = self.arp_table[nexthopip][0]
                        sendpkt = e + \
                            packet.get_header(IPv4) + packet.get_header(ICMP)
                        self.net.send_packet(intf, sendpkt)
                    else:  # nexthopip not in arptable,need to be put into a queue and send arp request
                        if nexthopip in self.ipv4packetqueue:
                            self.ipv4packetqueue[ip_address(nexthopip)].ippacket.append(packet)
                        else:
                            intf = self.forwarding_table[pos][3]
                            arprequest = create_ip_arp_request(self.net.interface_by_name(
                                intf).ethaddr, self.net.interface_by_name(intf).ipaddr, nexthopip)
                            self.net.send_packet(intf, arprequest)
                            ippacketqueue = ippacketinqueue(
                                [packet], time.time(), 1, arprequest, intf)
                            self.ipv4packetqueue[ip_address(nexthopip)] = ippacketqueue

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                self.checkqueue()
                recv = self.net.recv_packet(timeout=1.0)
                
                
            except NoPackets:
                #self.checkqueue()
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
