import ntop
import json
import host
import interface
# Import modules for CGI handling
import cgi
import sys

def identify_interface_index(ifname):
	"""Identifies the interface index for the given interface name.
	This is used in order to extract hosts from teh correct interface.
	if ifname is nil it returns 0
	"""
	if ifname == '': return 0
	
	for i in range(interface.numInterfaces()):
		if (interface.name(i).lower() == ifname.lower()):
			return i
			
	return 0

	
def insort_rightReversed(a, x, lo=0, hi=None):
	"""Insert item x in list a, and keep it sorted assuming a is sorted.
    If x is already in a, insert it to the right of the rightmost x.
    Optional args lo (default 0) and hi (default len(a)) bound the
    slice of a to be searched.
	"""
	if lo < 0:
		raise ValueError('lo must be non-negative')
	if hi is None:
		hi = len(a)
	while lo < hi:
		mid = (lo+hi)//2
		if x[0] > a[mid][0]: hi = mid
		else: lo = mid+1
	a.insert(lo, x)
	# returns insert position
	return lo

def insort_leftReversed(a, x, lo=0, hi=None):
	"""Insert item x in list a, and keep it sorted assuming a is sorted.
    If x is already in a, insert it to the left of the leftmost x.
    Optional args lo (default 0) and hi (default len(a)) bound the
    slice of a to be searched.
	"""
	if lo < 0:
		raise ValueError('lo must be non-negative')
	if hi is None:
		hi = len(a)
	while lo < hi:
		mid = (lo+hi)//2
		if a[mid][0] > x[0]: lo = mid+1
		else: hi = mid
	a.insert(lo, x)
	# returns insert position
	return lo

__P2P__ = 2
__VOIP__ = 4
__PRINTER__ = 8
__DIRECTORY__ = 16
__WORKSTATION__ = 32
__HTTPHOST__ = 64
__FTPHOST__ = 128
__SERVER__ = 256
__MAILSERVER__ = 512
__DHCP__ = 1024

# form management
form = cgi.FieldStorage();

# How many top hosts?
topN = form.getvalue('max', default=10)
topN = int(topN)
# Top hosts for which interface?
selectedif = form.getvalue('if', default="")

# Want to order by download (0) or upload (1) ?
direction = form.getvalue('direction', default=0)
direction = int(direction)
# how many hosts on this interface?
totalHosts = 0

listTopHost=[]
topHostsByPeakThroughput = []
topHostsByAverageThroughput = []
topHostsByActualThroughput = []
topHostsByTransferedBytes = []
topHostsByTransferedPackets = []


ifIndex = identify_interface_index(selectedif)

topHostsByPeakThroughputMetadata = {'type':'updowntable','mode':'gauge','unit':'kbps','title':'Top Hosts by Throughput Peak'}
topHostsByAverageThroughputMetadata = {'type':'updowntable','mode':'gauge','unit':'kbps','title':'Top Hosts by Throughput Average'}
topHostsByActualThroughputMetadata = {'type':'updowntable','mode':'gauge','unit':'kbps','title':'Top Hosts by Actual Throughput'}
topHostsByTransferedBytesMetadata = {'type':'updowntable','mode':'counter','unit':'kB','title':'Top Hosts by Bytes'}
topHostsByTransferedPacketsMetadata = {'type':'updowntable','mode':'counter','unit':'packets','title':'Top Hosts by Packet Number'}

topHostsByPeakThroughputData = {}
topHostsByAverageThroughputData = {}
topHostsByActualThroughputData = {}
topHostsByTransferedBytesData = {}
topHostsByTransferedPacketsData = {}

while ntop.getNextHost(ifIndex):
	
	if host.ipAddress()=="":
		 #drop host with no throughput or no ip
		continue 
		
	geo = host.geoIP()
	country = geo.get('country_name', '')
	countryCode = geo.get('country_code', '')
	hostType = 0 + __P2P__*host.isP2P() + __VOIP__*(host.isVoIPHost()|host.isVoIPClient()|host.isVoIPGateway()) + __PRINTER__*host.isPrinter() + __DIRECTORY__*host.isDirectoryHost() + __WORKSTATION__*host.isWorkstation() + __HTTPHOST__*host.isHTTPhost() + __FTPHOST__*host.isFTPhost() + __SERVER__*host.isServer() + __MAILSERVER__*(host.isSMTPhost()|host.isPOPhost()|host.isIMAPhost()) + __DHCP__*(host.isDHCPClient()|host.isDHCPServer())

	thpSent=host.sendThpt()
	thpRcvd=host.receiveThpt()
	
	# set peak throughput
	# according to direction ( kBps )
	thpPeakSent = (thpSent['peak']*8)/1000
	thpPeakRcvd = (thpRcvd['peak']*8)/1000
	thpPeak = thpPeakSent
	if (direction == 1): thpPeak = thpPeakRcvd
	
	# set average throughput
	# according to direction
	thpAvgSent = (thpSent['average']*8)/1000
	thpAvgRcvd = (thpRcvd['average']*8)/1000
	thpAvg = thpAvgSent
	if (direction == 1): thpAvg = thpAvgRcvd
	
	# set actual throughput
	# according to direction
	thpActSent = (thpSent['actual']*8)/1000
	thpActRcvd = (thpRcvd['actual']*8)/1000
	thpAct = thpActSent
	if (direction == 1): thpAct = thpActRcvd
	
	# bytes sent/received
	# to kbytes
	bytesSent = host.bytesSent()/1000
	bytesRcvd = host.bytesRcvd()/1000
	
	bytes = bytesSent
	if (direction == 1): bytes = bytesRcvd
	
	packetsSent = host.pktSent()
	packetsRcvd = host.pktRcvd()

	packets = packetsSent
	if (direction == 1): packets = packetsRcvd    

	#INSERT into the list using the bisect costs only O(logN)
	# might be cpu consuming
	insort_rightReversed(topHostsByPeakThroughput,  (thpPeak, {'hostname':host.hostResolvedName(),'macaddress':host.ethAddress(),'hardware':host.hwModel(), 'type':hostType, 'ip':host.ipAddress(), 'up':thpPeakSent, 'down':thpPeakRcvd, 'country':countryCode, 'direction':direction}))
	insort_rightReversed(topHostsByAverageThroughput,  (thpAvg, {'hostname':host.hostResolvedName(),'macaddress':host.ethAddress(),'hardware':host.hwModel(), 'type':hostType, 'ip':host.ipAddress(), 'up':thpAvgSent, 'down':thpAvgRcvd, 'country':countryCode, 'direction':direction}))
	insort_rightReversed(topHostsByActualThroughput,  (thpPeak, {'hostname':host.hostResolvedName(),'macaddress':host.ethAddress(),'hardware':host.hwModel(), 'type':hostType, 'ip':host.ipAddress(), 'up':thpActSent, 'down':thpActRcvd, 'country':countryCode, 'direction':direction}))
	insort_rightReversed(topHostsByTransferedBytes,  (bytes, {'hostname':host.hostResolvedName(),'macaddress':host.ethAddress(),'hardware':host.hwModel(), 'type':hostType, 'ip':host.ipAddress(), 'up':bytesSent, 'down':bytesRcvd, 'country':countryCode, 'direction':direction}))
	insort_rightReversed(topHostsByTransferedPackets,  (packets, {'hostname':host.hostResolvedName(),'macaddress':host.ethAddress(),'hardware':host.hwModel(), 'type':hostType, 'ip':host.ipAddress(), 'up':packetsSent, 'down':packetsRcvd, 'country':countryCode, 'direction':direction}))
	
	
# cut lists
if len(topHostsByPeakThroughput)>topN and topN>0:
	topHostsByPeakThroughput=topHostsByPeakThroughput[:topN]
if len(topHostsByAverageThroughput)>topN and topN>0:
	topHostsByAverageThroughput=topHostsByAverageThroughput[:topN]
if len(topHostsByActualThroughput)>topN and topN>0:
	topHostsByActualThroughput=topHostsByActualThroughput[:topN]
if len(topHostsByTransferedBytes)>topN and topN>0:
	topHostsByTransferedBytes=topHostsByTransferedBytes[:topN]
if len(topHostsByTransferedPackets)>topN and topN>0:
	topHostsByTransferedPackets=topHostsByTransferedPackets[:topN]

# incapsulate for consistency with other topics
topHostsByPeakThroughputData = {'hostlist':[el[1] for el in topHostsByPeakThroughput]}
topHostsByAverageThroughputData = {'hostlist':[el[1] for el in topHostsByAverageThroughput]}
topHostsByActualThroughputData = {'hostlist':[el[1] for el in topHostsByActualThroughput]}
topHostsByTransferedBytesData = {'hostlist':[el[1] for el in topHostsByTransferedBytes]}
topHostsByTransferedPacketsData = {'hostlist':[el[1] for el in topHostsByTransferedPackets]}


# build json array of pages to send to the iphone.
topHostsByPeakThroughputPage = {'metadata':topHostsByPeakThroughputMetadata, 'data': topHostsByPeakThroughputData}
topHostsByAverageThroughputPage = {'metadata':topHostsByAverageThroughputMetadata, 'data': topHostsByAverageThroughputData}
topHostsByActualThroughputPage = {'metadata':topHostsByActualThroughputMetadata, 'data': topHostsByActualThroughputData}
topHostsByTransferedBytesPage = {'metadata':topHostsByTransferedBytesMetadata, 'data': topHostsByTransferedBytesData}
topHostsByTransferedPacketsPage = {'metadata':topHostsByTransferedPacketsMetadata, 'data': topHostsByTransferedPacketsData}

#pages
pages = [topHostsByPeakThroughputPage, topHostsByAverageThroughputPage, topHostsByActualThroughputPage, topHostsByTransferedBytesPage, topHostsByTransferedPacketsPage]

ntop.sendHTTPHeader(1) # 1 = HTML
ntop.sendString(json.dumps({'tophosts':pages}, sort_keys=False, indent=4))
