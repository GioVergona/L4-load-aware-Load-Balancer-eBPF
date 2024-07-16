#!/usr/bin/env python3
#
# Copyright (c) Networked Systems Group (NSG) ETH Zürich.
import sys
import socket
import random
from subprocess import Popen, PIPE
import argparse
from random import randint
from scapy.all import sendp, get_if_list, get_if_hwaddr
from scapy.all import Ether, IP, UDP, ARP, srp, Raw


def send_fixed(n_flows: int, n_packets:int, iface:str, VIP, mac_dst) -> None:

    """
    - The program will send a fixed amount of packets per flow
    - The flow will be generated assigning a RANDOM IP SOURCE.
    - It will first send all the packets of one flow before passing to the next flow
    
    PACKET FORMAT: 
        ETH [
                - src_address = mac address of the interface,
                - dst_address = destination mac address, 
                - protocol_type = 0x0800
            ]
        IP [
            - src = random_IP
            - dst = VIP
            ]
        UDP []

    INPUT:
    - n_flows
    - n_packets (per flow)
    - iface
    - VIP
    - mac_dst

    """
    print("STARTING SENDING PACKETS")
    tos = 0
    ip_dst = socket.gethostbyname(VIP)
    ether_dst = mac_dst
    #payload = b"12345678910121213"

    for i in range(n_flows): 
        #IP address random come sender 
        ip_src = "".join([str(random.randint(0,255)) + "." for _ in range(3)]) + str(random.randint(0,255))
        print(f"[IP SRC]: {ip_src}")
        	
        if not ether_dst:
            print("Mac address for %s was not found in the ARP table" % ip_src)
            exit(1)

        print("Sending on interface %s to %s" % (iface, str(ip_dst)))
        pkt =  Ether(src=get_if_hwaddr(iface), dst=ether_dst, type = 0x0800)
        pkt = pkt /IP(src = ip_src, dst=ip_dst,tos=tos)
        pkt = pkt / UDP()
        print(pkt)
        
        for j in range(n_packets): 
            sendp(pkt, iface=iface, verbose=False)
            
    

def send_random(n_flows: int, max_packets: int, iface: str, VIP, mac_dst) -> None:
    """
    - The program will send a random amount of packets [1, max_packets]
    - The flow will be generated assigning a RANDOM IP SOURCE.
    - It will first send all the packets of one flow before passing to the next flow
    - It will produce a picture of the distribution of packets that will be stored in the current
        directory 
    
    
    PACKET FORMAT: 
        ETH [
                - src_address = mac address of the interface,
                - dst_address = destination mac address, 
                - protocol_type = 0x0800
            ]
        IP [
            - src = random_IP
            - dst = VIP
            ]
        UDP []

    INPUT:
    - n_flows
    - n_packets (per flow)
    - iface
    - VIP
    - mac_dst

    """
    
    print("STARTING SENDING PACKETS")
    tos = 0
    ip_dst = socket.gethostbyname(VIP)
    ether_dst = mac_dst

    
    dictionary = {} #Dictionary used for the graph
    for i in range(n_flows): 
        #IP address random come sender 
        ip_src = "".join([str(random.randint(0,255)) + "." for _ in range(3)]) + str(random.randint(0,255))
        print(f"[IP SRC]: {ip_src}")

        #UDP port random src 
        #UDP random port destination 
        	
        if not ether_dst:
            print("Mac address for %s was not found in the ARP table" % ip_src)
            exit(1)

        print("Sending on interface %s to %s" % (iface, str(ip_dst)))
        pkt =  Ether(src=get_if_hwaddr(iface), dst=ether_dst, type = 0x0800)
        pkt = pkt /IP(src = ip_src, dst=ip_dst,tos=tos)
        pkt = pkt / UDP()
        
        #Randomly selecting the amount of packets
        n_packets = random.randint(1,max_packets)
        
        dictionary[ip_src] = n_packets

        for j in range(n_packets): 
            sendp(pkt, iface=iface, verbose=False)    
    

def get_dst_mac(ip: str, iface:str, verbose: bool = False) -> str: 
    """
    This function retrieve the destination mac address using ARP protocol
    It will send the ARP request
    Then it will wait for the ARP reply 


    """

    # Create an ARP request packet
    arp_request = ARP(pdst=ip)
    # Create an Ethernet frame to encapsulate the ARP request
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    # Combine the Ethernet frame and ARP request into a single packet
    arp_request_broadcast = broadcast / arp_request
    
    # Send the packet and receive the response
    answered_list, _ = srp(arp_request_broadcast, timeout=3, iface="veth1", verbose=verbose)

    if verbose: 
        print(answered_list[0])
        print(answered_list[0][1])

    mac_dst = answered_list[0][1].hwsrc
    print(f"The MAC address is: {mac_dst}")

    return mac_dst



def main():

    
    #TAKING INPUTS FROM COMMAND LINE
    parser = argparse.ArgumentParser(description='Script to send packets to a specific destination')
    parser.add_argument("-i", "--interface", required=True, type=str, help="Interfaccia alla quale mandare il pacchetto")
    parser.add_argument("-p", "--packets", required=False, type=int, help="Number of packets per flow")
    parser.add_argument("-f", "--nflows", required=True, type=int, help="Total number of flows") 
    parser.add_argument("-maxp", "--maxpackets", required=False, type=int, help="Setting maximum number of packets per flow")

    config = "config.yaml"
    #OPEN FILE YAML AND EXTRACT THE VIP
    with open(config, "r") as f:
        _ = f.readline()
        line = f.readline()
        VIP = line.split(":")[1].strip()
        print(f"The virtual ip is: {VIP}")
        flag = False
    
    if flag: 
    	#The read of the yaml did not enter in errors
        print(f"[ERROR]: Could not read the configuration file: {config}")
        exit(1)
    	
    
    #Inserting values in variables
    args = parser.parse_args()
    iface = args.interface
    n_packets = args.packets
    n_flows = args.nflows
    max_packets = args.maxpackets
    
    #This is the namespace ip address from which i want 
    #to retrieve ARP 
    root = "10.0.0.1"
    ip_dst = socket.gethostbyname(root)
    mac_dst = get_dst_mac(ip_dst, iface, False)
    
    print(f"IP destination: {ip_dst}")
    
    if n_packets is None and max_packets is None:
        print("SENDING 15 packets per flow")
        send_random(n_flows, 15, iface, VIP,mac_dst)
    	
    elif n_packets is None:
        print("Sending random amount of packets up to max_packets")
        send_random(n_flows, max_packets, iface, VIP, mac_dst)
    	
    else:
        print(f"SENDING {n_packets} number of packets per {n_flows} flows")
        send_fixed(n_flows, n_packets, iface, VIP, mac_dst)


   


if __name__ == '__main__':
    main()
