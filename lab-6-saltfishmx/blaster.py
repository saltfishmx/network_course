#!/usr/bin/env python3

import time
import os
from random import randint
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blaster:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasteeIp,
            num,
            length="100",
            senderWindow="5",
            timeout="300",
            recvTimeout="100"
    ):
        self.net = net
        self.blasteeip = blasteeIp
        self.num = num
        self.length = length
        self.sw = senderWindow
        self.timeout = float(timeout)/1000 
        self.recvtimeout = float(recvTimeout)/1000
        self.lhs= 0
        self.rhs= 0
        self.notacklist = []
        self.resendtime = 0
        self.resendpos=0
        self.firstsend = -1
        self.lastacked = -1
        self.retxnum = 0
        self.coarsetonum = 0
        self.throughputnum = 0
        self.goodputnum = 0
        # TODO: store the parameters
        ...
    def make_packet(self,seqnum):
        e=Ethernet()
        e.src = '10:00:00:00:00:01'
        e.dst = '40:00:00:00:00:01'
        ip =IPv4(protocol=IPProtocol.UDP)
        ip.src = '192.168.100.1'
        ip.dst = '192.168.100.2'
        udp = UDP()
        seq = seqnum.to_bytes(4,"big")
        len =int(self.length).to_bytes(2,"big")
        variable = os.urandom(int(self.length))
        pkt = e + ip + udp + seq + len +variable

        return pkt 
    
    def printmessage(self):
        totalTXtime = self.lastacked-self.firstsend
        print("Total TX time (in seconds): {}\n".format(totalTXtime))

        print("Number of reTX : {}\n".format(self.retxnum))

       

        print("Number of coarse TOs : {}\n".format(self.coarsetonum))

        print("Throughput (Bps) : {}\n".format(self.throughputnum/totalTXtime))
        print("Goodput (Bps) : {}\n".format(self.goodputnum/totalTXtime))


    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_debug("I got a packet")
        raw = packet.get_header(RawPacketContents)
        seq = int.from_bytes(raw.data[:4],'big')
        if self.resendpos>0:
            self.resendpos-=1
        if seq == int(self.num)-1:
            self.lastacked = time.time()
        if seq == self.notacklist[0]:
            if len(self.notacklist)==1:
                self.lhs = self.rhs+1
            else :
                self.lhs = self.notacklist[1]
            self.resendtime=time.time()
            self.resendpos = 0
        self.notacklist.remove(seq)
        if self.rhs == int(self.num)-1 and len(self.notacklist)==0:
            self.printmessage()
            self.shutdown()

    def handle_no_packet(self):
        log_debug("Didn't receive anything")
        
        #log_info("self.rhs-self.lhs+1 ={} ,self.sw={}\n".format(self.rhs -self.lhs +1,self.sw))
        #log_info("self.rhs-self.lhs+1 == self.sw ? :{}\n".format(int(self.rhs -self.lhs +1)==int(self.sw)))
        #log_info("len(self.notacklist)!=0 :{}\n".format(len(self.notacklist)!=0 ))
        if len(self.notacklist)!=0 and (int(self.rhs -self.lhs +1) == int(self.sw) or self.rhs == int(self.num)-1): #resend
            log_info("1:  self.rhs={},self.lhs={}\n".format(self.rhs,self.lhs))
            log_info("notacklist looks like : {}\n".format(self.notacklist))
            #log_info("time.time()-self.resendtime>float(self.timeout)? :{}\n".format(time.time()-self.resendtime>float(self.timeout) ))
            #log_info("time.time(){} self.resendtime {} float(self.timeout) {}\n".format(time.time(),self.resendtime,float(self.timeout)))
            log_info("self.resendpos :{} len(self.notacklist:{}\n".format(self.resendpos,len(self.notacklist )))
            if time.time()-self.resendtime>float(self.timeout) and self.resendpos<len(self.notacklist):
                pkt = self.make_packet(self.notacklist[self.resendpos])
                itf = self.net.interface_by_name('blaster-eth0')
                self.net.send_packet(itf,pkt)
                self.retxnum +=1
                self.resendpos+=1
                self.throughputnum +=int(self.length)

                if self.resendpos == len(self.notacklist):
                    self.resendtime = time.time()
                    self.resendpos = 0
                    self.coarsetonum+=1                


        # Creating the headers for the packet

        # Do other things here and send packet
        elif self.rhs-self.lhs+1<int(self.sw):
            log_info("2 :self.rhs={},self.lhs={}\n".format(self.rhs,self.lhs))
            if self.rhs == int(self.num)-1:
                return 

            if self.rhs==0:
                self.firstsend=time.time()
            self.rhs +=1
            pkt = self.make_packet(self.rhs)
            itf = self.net.interface_by_name('blaster-eth0')
            self.net.send_packet(itf,pkt)
            self.notacklist.append(self.rhs)
            self.throughputnum +=int(self.length)
            self.goodputnum +=int(self.length)
        ...

    def start(self):
        '''A running daemon of the blaster.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                self.handle_no_packet()
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.shutdown()

    def shutdown(self):
        
        self.net.shutdown()


def main(net, **kwargs):
    blaster = Blaster(net, **kwargs)
    blaster.start()
