'''DNS Server for Content Delivery Network (CDN)
'''

import sys
from socketserver import UDPServer, BaseRequestHandler
from utils.dns_utils import DNS_Request, DNS_Rcode
from utils.ip_utils import IP_Utils
from datetime import datetime
import math
import random
import re
from collections import namedtuple


DNSItem = namedtuple("DNSItem", ("domain", "type", "values"))

CNAME = "CNAME"
A = "A"

__all__ = ["DNSServer", "DNSHandler"]


class DNSServer(UDPServer):
    def __init__(self, server_address, dns_file, RequestHandlerClass, bind_and_activate=True):
        super().__init__(server_address, RequestHandlerClass, bind_and_activate=True)
        self._dns_table = []
        self.parse_dns_file(dns_file)
        
    def parse_dns_file(self, dns_file):
        # ---------------------------------------------------
        # TODO: your codes here. Parse the dns_table.txt file
        # and load the data into self._dns_table.
        # --------------------------------------------------
        with open(dns_file, "r") as f:
            
            for line in f:
                substr = line.split()

                li = []
                i = 2
                while i<len(substr):
                    li.append(substr[i])
                    i += 1 
                item = DNSItem(domain=substr[0],type = substr[1],values = li)     
                self._dns_table.append(item)

        ...

    @property
    def table(self):
        return self._dns_table


class DNSHandler(BaseRequestHandler):
    """
    This class receives clients' udp packet with socket handler and request data. 
    ----------------------------------------------------------------------------
    There are several objects you need to mention:
    - udp_data : the payload of udp protocol.
    - socket: connection handler to send or receive message with the client.
    - client_ip: the client's ip (ip source address).
    - client_port: the client's udp port (udp source port).
    - DNS_Request: a dns protocl tool class.
    We have written the skeleton of the dns server, all you need to do is to select
    the best response ip based on user's infomation (i.e., location).

    NOTE: This module is a very simple version of dns server, called global load ba-
          lance dns server. We suppose that this server knows all the ip addresses of 
          cache servers for any given domain_name (or cname).
    """
    
    def __init__(self, request, client_address, server):
        self.table = server.table
        super().__init__(request, client_address, server)

    def calc_distance(self, pointA, pointB):
        ''' TODO: too naive '''
        return math.sqrt((pointA[0]-pointB[0])**2 + (pointA[1]-pointB[1])**2)

    def findDomain(self, reqDomain):
        for item in self.table:
            print(f"reqDomain:{reqDomain},have:{item.domain}\n")
            if item.domain[0]=='*' and item.domain[1]=='.':
                i = 0
                while reqDomain[i]!='.':
                    i+=1
                i += 1
                sub = reqDomain[i:]
                print(f"sub:{sub},item.domain[2:]:{item.domain[2:]}\n")
                if sub == item.domain[2:] or sub == item.domain[2:]+'.': 
                    print("match1!\n")
                    return item
            if item.domain == reqDomain:
                print("match2!\n")
                return item 
                        
        return None

    def get_response(self, request_domain_name):
        response_type, response_val = (None, None)
        # ------------------------------------------------
        # TODO: your codes here.
        # Determine an IP to response according to the client's IP address.
        #       set "response_ip" to "the best IP address".
        client_ip, _ = self.client_address
        ...
        item = self.findDomain(request_domain_name)
        if item:
            #print (f"client_ip={client_ip},{type(client_ip)}\n")
            print (f"item[0]={item[0]},{type(item[0])}\n")
            print (f"item[1]={item[1]},{type(item[1])}\n")
            if item[1] == "CNAME":
                response_type = "CNAME"
                response_val = str(item[2][0])
            else :
                response_type = "A"
                print(f"item:{item}\n")
                if len(item[2])>1:
                    res = IP_Utils.getIpLocation(client_ip)
                    print(f"res={res}\n")
                    if not res:
                        ra = random.randint(0,len(item[2])-1)
                        response_val = str(item[2][ra])
                    else:
                        min = float('inf')
                        minip = 0
                        for key in item[2]:
                            p = IP_Utils.getIpLocation(key)
                            print(f"p={p}\n")
                            if self.calc_distance(p,res)<min:
                                min = self.calc_distance(p,res)
                                minip = key
                        response_val = str(minip)
                        print(f"resposeval={response_val}\n")
                else :
                    response_val = str(item[2][0])
           

        # -------------------------------------------------
        return (response_type, response_val)

    def handle(self):
        """
        This function is called once there is a dns request.
        """
        ## init udp data and socket.
        udp_data, socket = self.request

        ## read client-side ip address and udp port.
        client_ip, client_port = self.client_address

        ## check dns format.
        valid = DNS_Request.check_valid_format(udp_data)
        if valid:
            ## decode request into dns object and read domain_name property.
            dns_request = DNS_Request(udp_data)
            request_domain_name = str(dns_request.domain_name)
            self.log_info(f"Receving DNS request from '{client_ip}' asking for "
                          f"'{request_domain_name}'")

            # get caching server address
            response = self.get_response(request_domain_name)

            # response to client with response_ip
            if None not in response:
                dns_response = dns_request.generate_response(response)
            else:
                dns_response = DNS_Request.generate_error_response(
                                             error_code=DNS_Rcode.NXDomain)
        else:
            self.log_error(f"Receiving invalid dns request from "
                           f"'{client_ip}:{client_port}'")
            dns_response = DNS_Request.generate_error_response(
                                         error_code=DNS_Rcode.FormErr)

        socket.sendto(dns_response.raw_data, self.client_address)

    def log_info(self, msg):
        self._logMsg("Info", msg)

    def log_error(self, msg):
        self._logMsg("Error", msg)

    def log_warning(self, msg):
        self._logMsg("Warning", msg)

    def _logMsg(self, info, msg):
        ''' Log an arbitrary message.
        Used by log_info, log_warning, log_error.
        '''
        info = f"[{info}]"
        now = datetime.now().strftime("%Y/%m/%d-%H:%M:%S")
        sys.stdout.write(f"{now}| {info} {msg}\n")