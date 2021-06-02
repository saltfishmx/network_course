'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
from switchyard.lib.userlib import *
from collections import deque 

def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    switch_table=deque(maxlen=5)
    #maxsize=5
    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break

        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        find = False
        for i,[mac,entry,volume] in enumerate(switch_table):
            if eth.src == mac :
                find = True
                if entry != fromIface:
                    switch_table[i]=[mac,fromIface,volume] 
        if find == False:
            if len(switch_table)==5:
                a,b,minnum = switch_table[0]
                k=0
                for i,[mac,entry,volume] in enumerate(switch_table):
                    if volume < minnum:
                        k=i
                        minnum=volume
                
                log_info(f"deleting the entry :{switch_table[k]}")
                switch_table.remove(switch_table[k])
                switch_table.append([eth.src,fromIface,0])
            else:
                switch_table.append([eth.src,fromIface,0])

        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            find = False
            for i,[mac,entry,traffic] in enumerate(switch_table):
                if mac == eth.dst:
                    find = True
                    log_info(f"already in switch_table,send {packet} to {entry}")
                    net.send_packet(entry,packet)
                    switch_table[i]=[mac,entry,traffic+1]
            if find == False:
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info(f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)
        

    net.shutdown()
