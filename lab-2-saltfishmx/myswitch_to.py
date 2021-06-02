'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
import time
from switchyard.lib.userlib import *

def update(table,duration):
    for key in list(table):#runtime error dictionary changed size during iteration
        if time.time()-table[key][1]>duration:
            table.pop(key)

def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    switch_table={}
    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break
        
        
        
        
        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        
        eth = packet.get_header(Ethernet)

        #if eth.src in switch_table:
        #    if fromIface == switch_table[eth.src][0]:
        #        switch_table[eth.src][1]=time.time()
        #    else:
        #        switch_table[eth.src]=[fromIface,time.time()]
        #else:
        #    switch_table[eth.src]=[fromIface,time.time()]

        switch_table[eth.src]=[fromIface,time.time()]

        update(switch_table,10)    

        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            if eth.dst in switch_table:
                log_info(f"already in switch_table,send {packet} to {switch_table[eth.dst][0]}")
                net.send_packet(switch_table[eth.dst][0],packet)
            else:
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info(f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)
        

    net.shutdown()
