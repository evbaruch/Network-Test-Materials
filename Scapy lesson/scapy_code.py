from scapy.all import sniff, DNS, DNSQR, IP, UDP, send, sr1, show_interfaces, dev_from_index

# Capture 2 packets
p1 = sniff(count=2)

# Display the summary of the packets
p1.summary()

# the first packet
p1[0].show()

# Display the second packet filter by DNS function
def filter_DNS(packet):
    return DNS in packet
p2 = sniff(count=2, lfilter = filter_DNS)
p2[0].show()

"""
    If the "qr" bit is set to 0, it means the packet is a query,
    meaning it's a request sent to a DNS server asking for
    information (e.g., to resolve a domain name into an IP address).

    If the "qr" bit is set to 1, it means the packet is a response,
    meaning the DNS server is replying with the requested information.

###[ DNS ]###
           id        = 52407
           qr        = 0       <----
           opcode    = QUERY
           aa        = 0
           tc        = 0
           rd        = 1
           ra        = 0
           z         = 0
           ad        = 0
           cd        = 0
           rcode     = ok
           qdcount   = 1
           ancount   = 0
           nscount   = 0
           arcount   = 0
           \qd        \
            |###[ DNS Question Record ]###
            |  qname     = b'www.msftconnecttest.com.'
            |  qtype     = A   <-----
            |  unicastresponse= 0
            |  qclass    = IN
           \an        \
           \ns        \
           \ar        \
"""

# type A is a query for an IPv4 address and itd equivalent to *1*
print(p2[0][DNSQR].qtype)

# type CNAME is a query for a canonical name and it's equivalent to *5*
# CNAME record points one domain to another domain. It is used when a domain or subdomain is redirected to another domain.
print(p2[0][DNSQR].qtype)

# this function filters the DNS query packets 
def filter_dns_A(packet):
    if DNS in packet:
        return (packet[DNS].qr==0) and (packet[DNSQR].qtype==1)

def print_query_name(dns_packet):
    print(dns_packet[DNSQR].qname)

# Capture 2 packets with the filter_dns_A function and print the query name
p3 = sniff(count=2, lfilter=filter_dns_A, prn = print_query_name)

# create a new packet
my_packet = IP()
my_packet.show()

# set the destination IP address
my_packet.dst = "8.8.8.8"
# my_packet = IP(dst="8.8.8.8")

# adding a DNS layer and UDP layer
my_packet = my_packet/UDP()/DNS()

# show the packet command
print(p3[0].command())

"""
Ether(dst='01:00:5e:00:00:fb', src='00:0f:02:0e:f9:53', type=2048)/IP(version=4, ihl=5, tos=0, len=67, id=35528, flags=0, frag=0, ttl=1, proto=17, chksum=35967, src='192.168.0.191', dst='224.0.0.251')/UDP(sport=5353, dport=5353, len=47, chksum=50453)/DNS(id=0, qr=0, opcode=0, aa=0, tc=0, rd=0, ra=0, z=0, ad=0, cd=0, rcode=0, qdcount=1, ancount=0, nscount=0, arcount=0, qd=[DNSQR(qname=b'BRW184F328C2C18.local.', qtype=1, unicastresponse=0, qclass=1)])
"""

# send the packet to the network
my_packet = IP(dst ='www.google.com') / 'Hello'
send(my_packet)

# send the packet to the network and wait for a response
p4 = IP(dst="8.8.8.8")/UDP(sport=55555, dport=53) /DNS(rd=1,qdcount=1)/DNSQR(qname="www.themarker.com", qtype=1)
r = sr1(p4, timeout=2) # verbose = False to hide the output
r.show()

# show the interfaces of network devices
show_interfaces()

"""
Source   Index  Name                          MAC                IPv4             IPv6
libpcap  1      Software Loopback Interface_  00:00:00:00:00:00  127.0.0.1        ::1
libpcap  10     Microsoft Wi-Fi Direct Virt_  Intel:3b:b4:89     169.254.10.250   fe80::e4fd:5b24:c4eb:e928     
libpcap  36     WAN Miniport (IP)
libpcap  4      Microsoft Wi-Fi Direct Virt_  ae:74:b1:3b:b4:88  169.254.24.230   fe80::cf1e:7a22:ff1b:3197     
libpcap  40     WAN Miniport (IPv6)
libpcap  44     WAN Miniport (Network Monit_
libpcap  8      Intel(R) Ethernet Connectio_  Dell:1e:21:7d      169.254.171.108  fe80::a7e1:db6f:42c3:dd27     
libpcap  9      Intel(R) Wi-Fi 6 AX201 160M_  Intel:3b:b4:88     192.168.0.189    2a02:14f:1f8:28b1:a433:938d:_ 
                                                                                  2a02:14f:1f8:28b1:46fd:def2:_ 
                                                                                  fe80::c508:5d1f:5c46:b396     
"""

# capture packets from a specific network device
p5 = sniff(count=2, iface=dev_from_index(9))    