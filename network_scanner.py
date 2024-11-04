#!/usr/bin/env python
from asyncio import timeout
import optparse

import scapy.all as scapy
parser = optparse.OptionParser()
parser.add_option("--IP", dest="ip", help="ip orqali mac adresni aniqlang")
(options, arguments) = parser.parse_args()

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=0.2, verbose=False)[0]
    client_list = []
    for element in answered_list:
        client_dict = {"IP": element[1].psrc, "MAC": element[1].hwsrc}
        client_list.append(client_dict)

    return client_list

def print_result(result_list):
    print("IP\t\t\tMAC Adress\n-------------------------------------------------")
    for client in result_list:
        print(client["IP"] + "\t\t" + client["MAC"])

scan_result = scan(options.ip)
print_result(scan_result)
