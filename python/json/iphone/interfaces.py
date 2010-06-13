import ntop
import json
import host
import interface
import cgi
import sys

class Layout:
	"""Layout Class for iphone client layout management
	This gathers up a number of containers each containing
	a number of widgets.
	dump method simply returns the internal dictionary of containers
	the way the iphone API are expected to receive them, once JSON-ized
	"""
	def __init__(self):
		self.data = {}
		self.data['layout'] = []
	def addContainer(self, container):
		if (container):
			self.data['layout'].append(container.dump())
	def dump(self):
		return self.data

class WidgetContainer:
	"""Widget Container Class
	Just collects a number of Widget Objects and sets a number
	of container parameters so that the container is correctly
	handled by the iphone api.
	In the details:
	- id = identifier for the container. It's unique.
	  Using this ID the iphone clients look for an image with the same name
	  and creates a tab icon accordingly.
	- label = the label shown under the tab icon on the iphone client.
	- type = container type. As of now only __WidgetContainerTypeHorizontalScrolling__ is supported.
	- widgets = array of widget objects dump data ( dictionaries )
	"""
	__WidgetContainerTypeHorizontalScrolling__ = 0
	
	def __init__(self, properties = {}):
		self.data = properties
		self.data['widgets'] = []
	def addWidget(self, widget):
		if (widget):
			self.data['widgets'].append(widget.dump())
	def dump(self):
		return self.data
	def setId(self, identifier):
		self.data['id'] = identifier
	def setLabel(self, label):
		self.data['label'] = label
	def setType(self, containerType):
		self.data['type'] = containerType
	def setWidgets(self, widgets = []):
		self.data['widgets'] = widgets
	def setKeyAndValue(self, key, value):
		self.data[key] = value

class Widget:
	""" The Widget Object
	Can be any of the constantized values here below.
	As long as it's one of these kinds you can push whatever data on them, 
	it will be correctly displayed.
	Obviously, every kind of widget accepts its own data format.
	__WidgetTypePieChart__ Accepts a dictionary of <String> keys with <float> values
	__WidgetTypeBarChart__ As Above.
	__WidgetTypeGraph__ Currently unsupported as of iphone client 1.0
	__WidgetTypeMultiGraph__ Currently unsupported as of iphone client 1.0
	__WidgetTypeTable__ Accepts a dictionary of <String> keys with <String> values.
	                    Values can also be numeric here, they'll be 
	                    automatically formatted if the case.
	__WidgetTypeGroupedTable__ Accepts a dictionary of <String> keys and <Dictionary> values.
	                           Values here are <String> key and <String/Numeric> value dictionaries.
	__WidgetTypeTopHosts__ Accepts an array of Dictionaries, Dictionaries are a collection of values.
	                       As of now these values will be correctly displayed clientside:
	                       -'hostname' = the resolved name of the host, where possible.
	                       -'macaddress' = the ethernet mac address
	                       -'hardware'= hardware type ( currently unsupported )
	                       -'type' = type of the host ( will be iconized clientside if an image with the same name is found)
	                       -'ip' = ip of the host
	                       -'up' = sent stream value
	                       -'down' = received stream value
	                       -'country' = 3 char country code.
	                       -'direction' = 0/1 tells the direction of the data (sent/received)
	__WidgetTypeSearchableTopHosts__ As above but the list is searchable.
	"""
	__WidgetTypeUndefined__ = 0
	__WidgetTypePieChart__ = 1
	__WidgetTypeBarChart__ = 2
	__WidgetTypeGraph__ = 3
	__WidgetTypeMultiGraph__ = 4
	__WidgetTypeTable__ = 5
	__WidgetTypeGroupedTable__ = 6
	__WidgetTypeTopHosts__ = 7
	__WidgetTypeSearchableTopHosts__ = 8
	
	def __init__(self, properties = {}):
		self.data = properties
	def dump(self):
		return self.data
	def setProperties(self, properties = {}):
		self.data.update( properties )
	def setId(self, widgetId):
		self.data['id'] = widgetId
	def setType(self, widgetType):
		self.data['type'] = widgetType
	def setSourcePath(self, sourcepath):
		self.data['sourcepath'] = sourcepath
	def setTitle(self, widgetTitle):
		self.data['title'] = widgetTitle
	def setKeyAndValue(self, key, value):
		self.data[key] = value
	def removeKey(self, key):
		if (key in self.data):
			del self.data[key]

# SORTING FUNCTION
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
	
def filter_dict(data, predicate=lambda k, v: True):
	if (data == None or len(data) <= 0):
		return {}
	returnData = {}
	for k, v in data.items():
		if predicate(k, v):
			returnData[k] = v
	return returnData

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
__NTP__ = 2048

# Traffic direction in host coordinates
__DIRECTION_SENT__ = 0
__DIRECTION_RECEIVED__ = 1

# form management
form = cgi.FieldStorage()

#instance.py?query=layout&interface=<if-name>&client='iphone'&version=<version>
# what king of query?
query = form.getvalue('query', default="")

# what widget do you want data for?
# used only for non layout requests
widgetId = form.getvalue('widget', default="")

# How many top hosts?
topN = form.getvalue('max', default=10)
topN = int(topN)

# Want to order by download (0) or upload (1) ?
direction = form.getvalue('direction', default=__DIRECTION_RECEIVED__)
direction = int(direction)

# sent any search string?
search = form.getvalue('search', default='')

# back value from the choice selector we sent via layout data
choice = form.getvalue('choice', default='')

# What type of client?
client = form.getvalue('client', default="")

# What version of client?
version = form.getvalue('version', default=0)
version = float(version)

# What interface to query data from?
selectedInterface = form.getvalue('interface', default="")

data={}

for i in range(interface.numInterfaces()):
	# Only include selected interface/s
	if((len(selectedInterface) == 0) or (selectedInterface == interface.uniqueName(i))):
		# ===============================
		#   L A Y O U T  E M I T T E R
		# ===============================
		# Try to do a layout for the specified interface if any.
		if ('layout' == query.lower()):
			#inits a layout ( a serie of containers )
			layout = Layout()
			# ==========================
			# A Container for top hosts
			# ==========================
			container = WidgetContainer({'type':WidgetContainer.__WidgetContainerTypeHorizontalScrolling__,'id':'tophosts','label':'tophosts'})
			# put widgets in it
			container.addWidget( Widget({'type':Widget.__WidgetTypeSearchableTopHosts__,'id':'tophoststhroughput','title':'Top Hosts by Throughput','choices':['peak','average','actual'],'unit':'kbps'}) )
			container.addWidget( Widget({'type':Widget.__WidgetTypeSearchableTopHosts__,'id':'tophostspackets','title':'Top Hosts by Packet Rate','unit':'pps'}) )
			container.addWidget( Widget({'type':Widget.__WidgetTypeSearchableTopHosts__,'id':'tophostsbytes','title':'Top Hosts by Byte Rate','unit':'byte'}) )
			# add the container to the layout
			layout.addContainer(container)
			# ==============================
			# A Container for top protocols
			# ==============================
			container = WidgetContainer({'type':WidgetContainer.__WidgetContainerTypeHorizontalScrolling__,'id':'protocols','label':'protocols'})
			# put widgets in it
			container.addWidget( Widget({'type':Widget.__WidgetTypeBarChart__,'id':'protocolbytes','title':'Packet Statistics','mode':'counter','unit':'packets'}) )
			container.addWidget( Widget({'type':Widget.__WidgetTypePieChart__,'id':'protocolpackets','title':'Byte Statistics','mode':'counter','unit':'bytes'}) )
			container.addWidget( Widget({'type':Widget.__WidgetTypeBarChart__,'id':'securitypackets','title':'Security Packets Statistics','mode':'counter','unit':'packets'}) )
			# Add specific NetFLow Stats only for those interfaces that have them
			if(len(interface.netflowStats(i)) > 0):
				container.addWidget( Widget({'type':Widget.__WidgetTypeTable__,'id':'netflowstats','title':'NetFlow Statistics','mode':'counter','unit':'bytes'}) )
			# Add specific SFlow Stats only for those interfaces that have them
			if(len(interface.sflowStats(i)) > 0):
				container.addWidget( Widget({'type':Widget.__WidgetTypePieChart__,'id':'sflowstats','title':'SFlow Statistics','mode':'counter','unit':'bytes'}) )
			# Add specific CPackets Stats only for those interfaces that have them
			if(len(interface.cpacketStats(i)) > 0):
				container.addWidget( Widget({'type':Widget.__WidgetTypePieChart__,'id':'cpacketstats','title':'CPackets Statistics','mode':'counter','unit':'bytes'}) )
			# Tail an interface throughput overall at the end
			container.addWidget( Widget({'type':Widget.__WidgetTypeGroupedTable__,'id':'interfacethroughput','title':'Interface Throughtput','mode':'gauge'}) )
			# add the container to the layout
			layout.addContainer(container)
			# ========================
			# A Container for ip data
			# ========================
			container = WidgetContainer({'type':WidgetContainer.__WidgetContainerTypeHorizontalScrolling__,'id':'directions','label':'directions'})
			# put widgets in it
			container.addWidget( Widget({'type':Widget.__WidgetTypePieChart__,'id':'ipstats','title':'IP Statistics','mode':'counter','unit':'bytes'}) )
			container.addWidget( Widget({'type':Widget.__WidgetTypePieChart__,'id':'tcpstats','title':'TCP Statistics','mode':'counter','unit':'bytes'}) )
			container.addWidget( Widget({'type':Widget.__WidgetTypePieChart__,'id':'udpstats','title':'UDP Statistics','mode':'counter','unit':'bytes'}) )
			container.addWidget( Widget({'type':Widget.__WidgetTypePieChart__,'id':'icmpstats','title':'ICMP Statistics','mode':'counter','unit':'bytes'}) )
			# add the container to the layout
			layout.addContainer(container)
			# ===================================
			# A Container for interface overview
			# ===================================
			container = WidgetContainer({'type':WidgetContainer.__WidgetContainerTypeHorizontalScrolling__,'id':'interface','label':'interface'})
			# put widgets in it
			container.addWidget( Widget({'type':Widget.__WidgetTypeGroupedTable__,'id':'interfaceoverview','title':selectedInterface+' Overview'}) )
			# add the container to the layout
			layout.addContainer(container)
			# ================================
			# Dump all to json data structure
			# ================================
			data = layout.dump()
		# ======================================
		#   W I D G E T  D A T A  E M I T T E R
		# ======================================
		# Actually populate data if you provided a widget identifier
		if ('widget' == query.lower() and len(widgetId) > 0):
			widget = Widget()
			# ===============================
			# Interface Overview Widget Data
			# ===============================
			if (widgetId.lower() == "interfaceoverview"):
				# generic info group
				widget.setKeyAndValue('generic info', 
					{'name':interface.name(i), 
					 'human name':interface.humanName(i), 
					 'virtual':'Yes' if interface.virtual(i) else 'No', 
					 'speed':interface.speed(i) if interface.speed(i) else 'Unknown' , 
					 'mtu':interface.mtu(i), 
					 'bpf filter':interface.bpf(i) or 'none'})
				# interface time group
				# suspended at the moment
				# widget.setKeyAndValue('interface time', interface.time(i))
				# interface address info 
				widget.setKeyAndValue('interface address', 
					{'IPv4 address': interface.ipv4(i), 
					 'IPv6 address': interface.ipv6(i), 
					 'network': interface.network(i), 
					 'active host number': interface.numHosts(i)})
			# ===============================
			# IP Statistics Widget Data
			# ===============================
			if (widgetId.lower() == "ipstats"):
				# pie chart is a serie of key-value pairs
				widget.setProperties(interface.ipStats(i))
			# ===============================
			# TCP Statistics Widget Data
			# ===============================
			if (widgetId.lower() == "tcpstats"):
				# pie chart is a serie of key-value pairs
				widget.setProperties(interface.tcpStats(i))
			# ===============================
			# UDP Statistics Widget Data
			# ===============================
			if (widgetId.lower() == "udpstats"):
				# pie chart is a serie of key-value pairs
				widget.setProperties(interface.udpStats(i))
			# ===============================
			# ICMP Statistics Widget Data
			# ===============================
			if (widgetId.lower() == "icmpstats"):
				# pie chart is a serie of key-value pairs
				widget.setProperties(interface.icmpStats(i))
			# ===============================
			# Protocol Bytes Widget Data
			# ===============================
			if (widgetId.lower() == "protocolbytes"):
				# pie chart is a serie of key-value pairs
				wdata = interface.bytesStats(i)
				wdata = filter_dict(wdata, lambda k,v: v > 0)
				widget.setProperties(wdata)
				widget.removeKey('total')
			# ===============================
			# Protocol Packets Widget Data
			# ===============================
			if (widgetId.lower() == "protocolpackets"):
				# pie chart is a serie of key-value pairs
				wdata = interface.pktsStats(i)
				wdata = filter_dict(wdata, lambda k,v: v > 0)
				widget.setProperties(wdata)
				widget.removeKey('total')
			# ===============================
			# Security Packets Widget Data
			# ===============================
			if (widgetId.lower() == "securitypackets"):
				# table is a serie of key-value pairs
				wdata = interface.securityPkts(i)
				wdata = filter_dict(wdata, lambda k,v: v > 0)
				widget.setProperties(wdata)
				widget.removeKey('total')
			# ===============================
			# NetFlow Widget Data
			# ===============================
			if (widgetId.lower() == "netflowstats"):
				# pie chart is a serie of key-value pairs
				widget.setProperties(interface.netflowStats(i))
				widget.removeKey('total')
			# ===============================
			# SFlow Widget Data
			# ===============================
			if (widgetId.lower() == "sflowstats"):
				# pie chart is a serie of key-value pairs
				widget.setProperties(interface.sflowStats(i))
				widget.removeKey('total')
			# ===============================
			# CPackets Widget Data
			# ===============================
			if (widgetId.lower() == "cpacketstats"):
				# pie chart is a serie of key-value pairs
				widget.setProperties(interface.cpacketStats(i))
				widget.removeKey('total')
			# =================================
			# Interface Throughput Widget Data
			# =================================
			if (widgetId.lower() == "interfacethroughput"):
				# grouped table is a serie of key-value pairs of dictionaries
				rs = interface.throughputStats(i)
				total = rs.pop('total',sum(rs.values()))
				widget.setKeyAndValue('actual', 
					{'packets':rs.pop('actualPkts',''), 
					 'bytes':rs.pop('actualBytes','')})
				widget.setKeyAndValue('peak', 
					{'packets':rs.pop('peakPkts',''), 
					 'bytes':rs.pop('peakBytes','')})
				widget.setKeyAndValue('last minute', 
					{'packets':rs.pop('lastMinPkts',''), 
					 'bytes':rs.pop('lastMinBytes','')})
				widget.setKeyAndValue('last 5 minutes', 
					{'packets':rs.pop('lastFiveMinsPkts',''), 
					 'bytes':rs.pop('lastFiveMinsBytes','')})
				if (len(rs) > 0): 
					widget.setKeyAndValue('other', rs)
			# ====================================
			# Top Hosts by Throughput Widget Data
			# ====================================
			if (widgetId.lower() == "tophoststhroughput"):
				topHosts = []
				while ntop.getNextHost(i):
					if (len(search) > 0 and  host.hostResolvedName().lower().find(search.lower()) == -1 and host.ethAddress().lower().find(search.lower()) == -1 and host.ipAddress().lower().find(search.lower()) == -1):
						continue
					if host.ipAddress()=="":
						 #drop host with no throughput or no ip
						continue
					geo = host.geoIP()
					country = geo.get('country_name', '')
					countryCode = geo.get('country_code', '')
					hostType = 0 + __P2P__*host.isP2P() + __VOIP__*(host.isVoIPHost()|host.isVoIPClient()|host.isVoIPGateway()) + __PRINTER__*host.isPrinter() + __DIRECTORY__*host.isDirectoryHost() + __WORKSTATION__*host.isWorkstation() + __HTTPHOST__*host.isHTTPhost() + __FTPHOST__*host.isFTPhost() + __SERVER__*host.isServer() + __MAILSERVER__*(host.isSMTPhost()|host.isPOPhost()|host.isIMAPhost()) + __DHCP__*(host.isDHCPClient()|host.isDHCPServer()) + __NTP__*(host.isNtpServer())

					thpSent=host.sendThpt()
					thpRcvd=host.receiveThpt()
					
					if (len(choice) <= 0):
						choice = 'peak'
					
					# set peak throughput
					# according to direction ( kBps )
					thpFilteredSent = (thpSent.get(choice,'')*8)/1000
					thpFilteredRcvd = (thpRcvd.get(choice,'')*8)/1000
					thpFiltered = thpFilteredSent
					if (direction == __DIRECTION_RECEIVED__): thpFiltered = thpFilteredRcvd
					# sort them
					insort_rightReversed(topHosts,  (thpFiltered, {'hostname':host.hostResolvedName(),'macaddress':host.ethAddress(),'hardware':host.hwModel(), 'type':hostType, 'ip':host.ipAddress(), 'up':thpFilteredSent, 'down':thpFilteredRcvd, 'country':countryCode, 'direction':direction}))
				
				# limit them
				if len(topHosts)>topN and topN>0:
					topHosts=topHosts[:topN]
				widget.setProperties({'hostlist':[el[1] for el in topHosts]})
			# ====================================
			# Top Hosts by Packet Rate Widget Data
			# ====================================
			if (widgetId.lower() == "tophostspackets"):
				topHosts = []
				while ntop.getNextHost(i):
					if (len(search) > 0 and search.lower() not in host.hostResolvedName() and search.lower() not in host.ethAddress() and search.lower() not in host.ipAddress()):
						continue
					if host.ipAddress()=="":
						 #drop host with no throughput or no ip
						continue
					geo = host.geoIP()
					country = geo.get('country_name', '')
					countryCode = geo.get('country_code', '')
					hostType = 0 + __P2P__*host.isP2P() + __VOIP__*(host.isVoIPHost()|host.isVoIPClient()|host.isVoIPGateway()) + __PRINTER__*host.isPrinter() + __DIRECTORY__*host.isDirectoryHost() + __WORKSTATION__*host.isWorkstation() + __HTTPHOST__*host.isHTTPhost() + __FTPHOST__*host.isFTPhost() + __SERVER__*host.isServer() + __MAILSERVER__*(host.isSMTPhost()|host.isPOPhost()|host.isIMAPhost()) + __DHCP__*(host.isDHCPClient()|host.isDHCPServer()) + __NTP__*(host.isNtpServer())
					
					packetsSent = host.pktSent()
					packetsRcvd = host.pktRcvd()

					packets = packetsSent
					if (direction == 1): packets = packetsRcvd
					
					# sort them
					insort_rightReversed(topHosts,  (packets, {'hostname':host.hostResolvedName(),'macaddress':host.ethAddress(),'hardware':host.hwModel(), 'type':hostType, 'ip':host.ipAddress(), 'up':packetsSent, 'down':packetsRcvd, 'country':countryCode, 'direction':direction}))

				# limit them
				if len(topHosts)>topN and topN>0:
					topHosts=topHosts[:topN]
				widget.setProperties({'hostlist':[el[1] for el in topHosts]})
			# ====================================
			# Top Hosts by Bytes Rate Widget Data
			# ====================================
			if (widgetId.lower() == "tophostsbytes"):
				topHosts = []
				while ntop.getNextHost(i):
					if (len(search) > 0 and search.lower() not in host.hostResolvedName() and search.lower() not in host.ethAddress() and search.lower() not in host.ipAddress()):
						continue
					if host.ipAddress()=="":
						 #drop host with no throughput or no ip
						continue
					geo = host.geoIP()
					country = geo.get('country_name', '')
					countryCode = geo.get('country_code', '')
					hostType = 0 + __P2P__*host.isP2P() + __VOIP__*(host.isVoIPHost()|host.isVoIPClient()|host.isVoIPGateway()) + __PRINTER__*host.isPrinter() + __DIRECTORY__*host.isDirectoryHost() + __WORKSTATION__*host.isWorkstation() + __HTTPHOST__*host.isHTTPhost() + __FTPHOST__*host.isFTPhost() + __SERVER__*host.isServer() + __MAILSERVER__*(host.isSMTPhost()|host.isPOPhost()|host.isIMAPhost()) + __DHCP__*(host.isDHCPClient()|host.isDHCPServer()) + __NTP__*(host.isNtpServer())

					# bytes sent/received
					# to kbytes
					bytesSent = host.bytesSent()/1000
					bytesRcvd = host.bytesRcvd()/1000

					bytes = bytesSent
					if (direction == 1): bytes = bytesRcvd

					# sort them
					insort_rightReversed(topHosts,  (bytes, {'hostname':host.hostResolvedName(),'macaddress':host.ethAddress(),'hardware':host.hwModel(), 'type':hostType, 'ip':host.ipAddress(), 'up':bytesSent, 'down':bytesRcvd, 'country':countryCode, 'direction':direction}))

				# limit them
				if len(topHosts)>topN and topN>0:
					topHosts=topHosts[:topN]
				widget.setProperties({'hostlist':[el[1] for el in topHosts]})
			
			tobesent = widget.dump()
			if ('hostlist' in tobesent):
				tobesent = tobesent.get('hostlist',[])
			data['widget'] = tobesent

ntop.sendHTTPHeader(1) # 1 = HTML
#ntop.sendString('<PRE>')
ntop.sendString(json.dumps(data, sort_keys=False, indent=4))
#ntop.sendString('</PRE>')