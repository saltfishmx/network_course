#!/usr/bin/env python3

import time
import threading
from struct import pack
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blastee:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasterIp,
            num
    ):
        self.net = net
        self.blasterIp=blasterIp
        self.num = num
        # TODO: store the parameters
        ...

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_debug(f"I got a packet from {fromIface}")
        log_debug(f"Pkt: {packet}")
        raw = packet.get_header(RawPacketContents)
        seq = int.from_bytes(raw.data[:4],'big').to_bytes(4,'big')
        payload = raw.data[6:]
        if len(payload)<8:
            payload += "\0".encode()*(8-len(payload))#padding
        payload = payload[0:8]
        e=Ethernet()
        e.src = '20:00:00:00:00:01'
        e.dst = '40:00:00:00:00:02'
        ip =IPv4(protocol=IPProtocol.UDP)
        ip.src = '192.168.200.1'
        ip.dst = '192.168.200.2'
        udp = UDP()
        sepkt = e + ip + udp + seq + payload
        itf = self.net.interface_by_name('blastee-eth0')
        self.net.send_packet(itf,sepkt)

    def start(self):
        '''A running daemon of the blastee.
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

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blastee = Blastee(net, **kwargs)
    blastee.start()
