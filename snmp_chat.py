from scapy.all import *
from scapy.layers.inet import UDP, IP
from scapy.layers.snmp import SNMPvarbind, SNMPget, SNMP
from base64 import b64encode, b64decode

import pyaes
import os
import sys
import time
import argparse
import hashlib


class AESCipher:
    """
    This class defines the functions to encrypt and decrypt messages with AES
    """
    def __init__(self, key):
        self.bs = 32
        self.key = hashlib.sha256(key.encode()).digest()
        self.iv = 27928000841356984726233357955409624076659936569171526749940232512655365051623  # secrets.randbits(256)

    def encrypt(self, pt):
        aes = pyaes.AESModeOfOperationCTR(self.key, pyaes.Counter(self.iv))
        ct = b64encode(aes.encrypt(pt))
        return ct

    def decrypt(self, ct):
        aes = pyaes.AESModeOfOperationCTR(self.key, pyaes.Counter(self.iv))
        pt = aes.decrypt(b64decode(ct))
        return pt


def create_snmp_packet(_destination_ip, _new_message, _community, _udp_port):
    """
    Create SNMP packet
    """
    p = IP(dst=_destination_ip) / UDP(sport=RandShort(), dport=_udp_port) / SNMP(community=_community, PDU=SNMPget(
        varbindlist=[SNMPvarbind(oid=ASN1_OID(_new_message))]))
    send(p, verbose=0)


def encrypt_message(_message, _key):
    """
    Encrypt message with AES algorithm if user set key
    """
    oid = "1.3"
    if _key == '':
        new_message = _message

        if len(new_message) > 128:
            print("[I] message is more than 128 bit")

        for cont in range(0, len(new_message)):
            des = str(ord(new_message[cont]))
            oid += "." + des
            je = len(new_message) - 1
            if cont == je:
                oid += ".0"

    else:
        crom = AESCipher(_key)
        new_message = crom.encrypt(_message)

        if len(new_message) > 128:
            print("[I] message is more than 128 bit")

        for cont in range(0, len(new_message)):
            oid += "." + str(new_message[cont])
            je = len(new_message) - 1
            if cont == je:
                oid += ".0"

    return oid


def snmp_values(__key, __community, __alias):
    """
    This function defines the prn of the scapy sniff
    """

    def sndr(pkt):
        a = " "
        d = " "
        rec_community = str(pkt[SNMP].community.val.decode("utf-8"))
        rec_oid = str(pkt[SNMPvarbind].oid.val)
        if rec_community == __community:
            for i in range(4, len(rec_oid)):
                if rec_oid[i] == ".":
                    d = d + chr(int(a))
                    a = " "
                else:
                    a = a + rec_oid[i]

            if __key != '':
                rec = AESCipher(__key)
                e_rec = rec.decrypt(d).decode("utf-8")
                if e_rec == "q":
                    print("\n[W] My friend left the session")
                else:
                    print("\n[*] My friend: " + e_rec)
                    print(__alias + "> ")
            else:
                if d == " q":
                    print("\n[W] My friend left the session")
                else:
                    print("\n[*] My friend: " + d)
                    print(__alias + "> ")

        else:
            print("\n[E] Authentication failed, verify community value")

    return sndr


def main():

    # Check That script run with root user
    if os.getuid() != 0:
        print("[E] Run script with superuser")
        sys.exit(1)

    # Define arguments
    parser = argparse.ArgumentParser(description='__SNMP covert channel__')
    parser.add_argument('-l', action="store", dest='LOCAL_IP', help='Local IP')
    parser.add_argument('-d', action="store", dest='DESTINATION_IP', help='Destination IP')
    parser.add_argument('-c', action="store", dest='COMMUNITY', help='SNMP Community')
    parser.add_argument('-e', action="store", dest='KEY', help='Key of AES algorithm')
    parser.add_argument('-p', action="store", dest='UDP_PORT', help='UDP port (Default: 161/UDP)')
    arguments = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    arguments = vars(arguments)

    if arguments['UDP_PORT'] is None:
        udp_port = 161  # Default SNMP port is 161/UDP
    else:
        udp_port = int(arguments['UDP_PORT'])

    if arguments['COMMUNITY'] is None:
        community = "public"
    else:
        community = arguments['COMMUNITY']

    if arguments['KEY'] is None:
        key = ''
    else:
        key = arguments['KEY']

    if arguments['DESTINATION_IP'] is None:
        print("[E] Set local IP")
        sys.exit()
    else:
        destination_ip = arguments['DESTINATION_IP']

    if arguments['LOCAL_IP'] is None:
        print("[E] Set destination IP")
        sys.exit()
    else:
        local_ip = arguments['LOCAL_IP']

    alias = input("[?] Enter your username: ")
    print("[I] For 'Quit' use 'q'")

    # Run Sniffer for capturing our SNMP packets
    filter_str = "udp and ip src " + destination_ip + " and port " + str(udp_port) + " and ip dst " + local_ip
    t = AsyncSniffer(prn=snmp_values(key, community, alias), filter=filter_str, store=0)
    t.start()

    message = input(alias + "> \n")
    while message != 'q':
        message = input(alias + "> \n")
        if message != '':
            oid = encrypt_message(message, key)
            create_snmp_packet(destination_ip, oid, community, udp_port)
            time.sleep(0.2)

    t.stop()
    print("[I] Goodbye!")
    sys.exit()


if __name__ == "__main__":
    main()
