"""
Module that exposes functions to get information on the current interfaces enabled in ntop.

"""

def numInterfaces():
    """
    Get number of configured interfaces
    """
    pass

def name():
    """
    Get interface name
    @rtype: String
    @return the name of the interface
    """
    pass

def uniqueName():
    """
    Get unique interface name
    @rtype: String
    @return the unique name of the interface
    """
    pass

def humanName():
    """
    Get human-friendly interface name
    @rtype: String
    @return the human-friendly name of the interface
    """
    pass

def ipv4(interfaceId):
    """
    Get interface address (IPv4)
    @type interfaceId: int
    @param interfaceId: the id number for the specified interface
    @rtype: string
    @return: the ipv4 address of the interfeceId passed. Empty string if none. Null if no interface passed
    """
    pass

def network(interfaceId):
    """
    Get network and mask to which the interface belongs
    @type interfaceId: int
    @param interfaceId: the id number for the specified interface
    @rtype: string 
    @return: the network and the network mask for the specified interfaceId
    """
    pass
def numHosts(interfaceId):
    """
    Get the number of hosts active on this interface
    @type interfaceId: int
    @param interfaceId: the id number for the specified interface
    @rtype: number
    @return: the number of hosts for the specified interfaceId
    """
    pass
def ipv6(interfaceId):
    """
    Get interface address (IPv6)
    @type interfaceId: int
    @param interfaceId: the id number for the specified interface
    @rtype: string
    @return: the ipv6 address of the interfeceId passed. Empty string if none. Null if no interface passed
    """
    pass
def time(interfaceId):
    """
    Get interface time
    @type interfaceId: int
    @param interfaceId: the id number for the specified interface
    @rtype: dictionary
    @return {'startTime':number, 'firstSeen': number, 'lastSeen': number}
    """
    pass
def virtual():
    """
    Check if this is a virtual interface
    """
    pass
def speed():
    """
    Interface speed (0 if unknown)
    """
    pass
def mtu():
    """
    Get interface MTU size
    """
    pass
def bpf():
    """
    Get BPF filter set for this interface (if any)
    """
    pass

def pktsStats():
    """
    Get packet statistics
    """
    pass

def fcPktsStats():
    """
    Get FC pkts stats
    """
    pass

def fcBytesStats():
    """
    Get FC byte stats
    """
    pass
def bytesStats():
    """
    Get bytes statistics
    """
    pass
def throughputStats():
    """
    """
    pass

def tcpStats():
    """
    Get TCP stats
    """
    pass

def udpStats():
    """
    Get UDP stats
    """
    pass
def icmpStats():
    """
    Get ICMP stats
    """
    pass
def ipStats():
    """
    Get IP stats
    """
    pass
def securityPkts():
    """
    Get information about security packets
    """
    pass
def netflowStats():
    """
    Get NetFlow interface information
    """
    pass
def sflowStats():
    """
    Get sFlow interface information
    """
    pass
def cpacketStats():
    """
    Get cPacket counter information
    """
    pass