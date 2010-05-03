"""
Module that exposes functions to get information on the current host taken into consideration
"""
def serial(): 
    """
    Get host unique serial identifier
    @rtype: string
    @return: the unique serial identifier
    """
    pass
def ethAddress():
    """
    Get host MAC address
    @rtype: string
    @return: the host MAC address
    """
    pass
def ipAddress():
    """
    Get host IP address
    @rtype: string
    @return: the IP address
    """
    pass
def hostResolvedName():
    """
    Get host Resolved Name
    @rtype: string
    @return: the host Resolved Name
    """
    pass
def hostTrafficBucket():
    """
    Get Traffic Bucket
    @rtype: number
    @return: host traffic bucket
    """
    pass
def numHostSessions():
    """
    Get actual numHostSessions
    @rtype: int
    @return: the number of host Sessions
    """
    pass
def vlanId():
    """
    Get vlanId
    @rtype: number
    @return: the vlanId
    """
    pass
def network_mask():
    """
    Get current host network_mask
    @rtype: number
    @return: the network mask
    """
    pass
def hwModel():
    """
    Get hwModel of the current host
    @rtype: string
    @return: the hardware model or empy string if no info
    """
    pass
def isHostResolvedNameType(type):
    """
    Check if the host matches the specified type
    @type type: number
    @param type: the type of the host resolved name to check
    @rtype: boolean
    @return: true if the host resolved name is of type type, false otherwise
    """
    pass
def isFTPhost():
    """
    Check FTP Host
    @rtype: boolean
    @return: true if the current host is ftp, false otherwise
    """
    pass
def isServer():
    """
    Check isServer
    @rtype: boolean
    @return: true if the current host is a Server, false otherwise
    """
    pass
def isWorkstation():
    """
    Check isWorkstation Host
    @rtype: boolean
    @return: true if the current host is a workstation, false otherwise
    """
    pass
def isMasterBrowser():
    """
    Check isMasterBrowser Host
    @rtype: boolean
    @return: true if the current host is a Master Browser, false otherwise
    """
    pass
def isMultihomed():
    """
    Check isMultihomed Host
    @rtype: boolean
    @return: true if the current host is multihomed, false otherwise
    """
    pass
def isMultivlaned():
    """
    Check isMultivlaned Host
    @rtype: boolean
    @return: true if the current host is multilaned, false otherwise
    """
    pass
def isPrinter():
    """
    Check isPrinter Host
    @rtype: boolean
    @return: true if the current host is a printer, false otherwise
    """
    pass
def isSMTPhost():
    """
    Check isSMTPhost Host
    @rtype: boolean
    @return: true if the current host is a smtp host, false otherwise
    """
    pass
def isPOPhost():
    """
    Check isPOPhost Host
    @rtype: boolean
    @return: true if the current host is a pop host, false otherwise
    """
    pass
def isIMAPhost():
    """
    Check isIMAPhost Host
    @rtype: boolean
    @return: true if the current host is an imap host, false otherwise
    """
    pass
def isDirectoryHost():
    """
    Check isDirectoryHost Host
    @rtype: boolean
    @return: true if the current host is a directory host, false otherwise
    """
    pass

def isHTTPhost():
    """
    Check isHTTPhost Host
    @rtype: boolean
    @return: true if the current host is an http host, false otherwise
    """
    pass
def isWINShost():
    """
    Check isWINShost Host
    @rtype: boolean
    @return: true if the current host is a wins host, false otherwise
    """
    pass
def isBridgeHost():
    """
    Check isBridgeHost Host
    @rtype: boolean
    @return: true if the current host is a bridge, false otherwise
    """
    pass
def isVoIPClient():
    """
    Check isVoIPClient Host
    @rtype: boolean
    @return: true if the current host is a voip client host, false otherwise
    """
    pass
def isVoIPGateway():
    """
    Check isVoIPGateway Host
    @rtype: boolean
    @return: true if the current host is a voip gateway, false otherwise
    """
    pass
def isVoIPHost():
    """
    Check isVoIPHost Host
    @rtype: boolean
    @return: true if the current host is a voip host, false otherwise
    """
    pass

def isDHCPClient():
    """
    Check isDHCPClient Host
    @rtype: boolean
    @return: true if the current host is a dhcp client, false otherwise
    """
    pass
def isDHCPServer():
    """
    Check isDHCPServer Host
    @rtype: boolean
    @return: true if the current host is a dhcp server, false otherwise
    """
    pass
def isP2P():
    """
    Check isP2P Host
    @rtype: boolean
    @return: true if the current host is a p2p host, false otherwise
    """
    pass
def isNtpServer():
    """
    Check isNtpServer Host
    @rtype: boolean
    @return: true if the current host is a ntp server, false otherwise
    """
    pass
def totContactedSentPeers():
    """
    Check totContactedSentPeers Host
    @rtype: number
    @return: the number of the total contacted sent peers
    """
    pass
def totContactedRcvdPeers():
    """
    Check totContactedRcvdPeers Host
    @rtype: number
    @return: the number of the total contacted received peers
    """
    pass
def fingerprint():
    """
    Check fingerprint Host
    @rtype: string
    @return: the fingerprint of the current host or empty string if none
    """
    pass
def synPktsSent():
    """
    Check synPktsSent Host
    @rtype: number
    @return: the number of syn packets sent by the current host
    """
    pass
def pktSent():
    """
    Return the number of packets sent by this host
    @rtype: number
    @return: the number packets sent
    """
    pass
def pktRcvd():
    """
    Return the number of packets rcvd by this host
    @rtype: number
    @return: the number of packets received
    """
    pass
def bytesSent():
    """
    Return the number of bytes sent by this host
    @rtype: number
    @return: the number of bytes sent
    """
    pass
def bytesRcvd():
    """
    Return the number of bytes rcvd by this host
    @rtype: number
    @return: the number of bytes received
    """
    pass
def sendThpt(type):
    """
    Return the send throughput
    @type type: string
    @param type: actual average peak the type of the sent throughput to get
    @rtype: number
    @return: the number of bytes of the sent throughput of type type
    """
    pass
def receiveThpt(type):
    """
    Return the receive throughput
    @type type: string
    @param type: actual average peak the type of the received throughput to get
    @rtype: number
    @return: the number of bytes of the received throughput of type type
    """
def geoIP():
    """
    Read geoLocalization info from GeoCityLite and return them
    @rtype: dictionary
    @return: a dictionary {'country_code':string,'country_name':string, 'region':string, 'city': string, 'latitude': number float, 'longitude': number float } 
            with all the geoLocation info retrieved by GeoCityLite for the current host    
    """
