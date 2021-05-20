# Created by FoxSinOfGreed1729 
# Many thanks to zaid sabih and udemy.com
import scapy.all as scapy
import subprocess


def get_mac(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast = broadcast / arp_req
    answered, unanswered = scapy.srp(arp_broadcast, timeout=2, verbose=False)
    print(answered[0][1].hwsrc)
    return answered[0][1].hwsrc


def sniffer(interface):
    scapy.sniff(iface=interface, store=False, prn=analysis)
    # iface stands for the interface we'd like to listen
    # store=False tells program not to store packet info in memory so that it doesn't put too much load
    # prn allows us to call a callback function
    # i.e. it will call a function each time it intercepts a packet
    # if we want to put a filter, theres another field - filters=''


def analysis(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        # op = 2 means it is arp response
        try:
            packet_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = get_mac(packet[scapy.ARP].hwsrc)
            # we're extracting mac address from 2 different methods.
            # first from the arp packet
            # next from get mac i.e. arp broadcast
            if packet_mac != response_mac:
                print("[+] ARP Spoof Detected")
        except IndexError:
            pass


def intro():
    while True:
        print("\n1>  Run Ifconfig to find out interfaces")
        print("2>  Enter Interface and start detection")
        choice = int(input("3>  Exit\n"))
        if choice == 1:
            subprocess.call('ifconfig')
        if choice == 2:
            interface = input('Enter Interface\n')
            sniffer(interface)
        if choice == 3:
            exit(1)


intro()
