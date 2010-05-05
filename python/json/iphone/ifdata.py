#
# (C) 2010 - David Votino
#
import ntop
import interface
import json

# Import modules for CGI handling
import cgi, cgitb

# Parse URL
cgitb.enable();

form = cgi.FieldStorage();

ifname = form.getvalue('if', default="")
topic = form.getvalue('topic', default="")


rsp = {}

try:
	for i in range(interface.numInterfaces()):
		
		# Only include selected interface/s
		if((len(ifname) == 0) or (ifname == interface.name(i))):
			
			# initialize output dictionary
			rsp[interface.uniqueName(i)] = {}
			
			if (len(topic) == 0 or topic.lower() == "interface"):
				# interface data is a grouped table.
				info_metadata = { "type":"groupedtable", "title":"Generic Interface Information" }
				info = {}

				# interface info 
				# formerly other info
				if_info = {}
				if_info['name'] = interface.name(i)
				if_info['humanName'] = interface.humanName(i)
				if_info['virtual'] = interface.virtual(i)
				if_info['speed'] = interface.speed(i)
				if_info['mtu'] = interface.mtu(i)
				if_info['bpf'] = interface.bpf(i)

				# Add interface info to interface data.
				info['generic info'] = if_info

				# add time info to interface data
				# this is a dictionary
				info['interface time'] = interface.time(i)

				# Interface address info
				if_addr = {}
				if_addr['ipv4 address'] = interface.ipv4(i)
				if_addr['ipv6 address'] = interface.ipv6(i)
				if_addr['network'] = interface.network(i)
				if_addr['n.hosts'] = interface.numHosts(i)
				
				# Add address info to interface data
				info['interface address'] = if_addr
			
				ifdata = [{"data" : info, "metadata" : info_metadata}]
				
				rsp[interface.uniqueName(i)]['interface'] = ifdata
			
			if (len(topic) == 0 or topic.lower() == "protocols"):
				
				# Statistics of the interface traffic
				rs = interface.pktsStats(i)
				total = rs.pop('total',sum(rs.values()))
				pktsStats = { "metadata": { "type":"barchart", "title":"Packet Statistics", "unit": "packets", "mode" : "counter", "total": total }, "data" : rs }
			
				rs = interface.bytesStats(i)
				total = rs.pop('total',sum(rs.values()))

				bytesStats = { "metadata": { "type":"piechart", "title":"Bytes Statistics", "unit": "bytes", "mode" : "counter", "total": total }, "data" : rs }

				rs = interface.throughputStats(i)
				total = rs.pop('total',sum(rs.values()))
				
				adapter = {}
				adapter['actual'] = {'packets': rs.pop('actualPkts',''), 'bytes': rs.pop('actualBytes','')}
				adapter['peak'] = {'packets': rs.pop('peakPkts',''), 'bytes': rs.pop('peakBytes','')}
				adapter['last minute'] = {'packets': rs.pop('lastMinPkts',''), 'bytes': rs.pop('lastMinBytes','')}
				adapter['last 5 minutes'] = {'packets': rs.pop('lastFiveMinsPkts',''), 'bytes': rs.pop('lastFiveMinsBytes','')}
				if (len(rs) > 0): adapter['other'] = rs
				
				throughputStats = { "metadata": { "type":"groupedtable", "title":"Interface Throughput", "unit": "bps", "mode" : "gauge", "total": total }, "data" : adapter }
			
				rs = interface.securityPkts(i)
				total = rs.pop('total',sum(rs.values()))
				securityPkts = { "metadata": { "type":"barchart", "title":"Security Packet Statistics", "unit": "packets", "mode" : "counter", "total": total}, "data" : rs }
				# Build traffic info for interface
				if_traffic = [pktsStats, bytesStats, securityPkts, throughputStats]
				
				rs = interface.netflowStats(i)
				if(len(rs) > 0):
					total = rs.pop('total',sum(rs.values()))
					if_traffic.append({"metadata": {"type":"table", "title":"Netflow Statistics", "unit": "bytes", "mode" : "counter", "total": total}, "data":rs})

				rs = interface.sflowStats(i)
				if(len(rs) > 0):
					total = rs.pop('total',sum(rs.values()))
					if_traffic.append({"metadata": {"type":"piechart", "title":"SFlow Statistics", "unit": "bytes", "mode" : "counter", "total": total}, "data":rs})

				rs = interface.cpacketStats(i)
				if(len(rs) > 0):
					total = rs.pop('total',sum(rs.values()))
					if_traffic.append({"metadata": {"type":"piechart", "title":"CPackets Statistics", "unit": "bytes", "mode" : "counter", "total": total}, "data":rs})
				
				rsp[interface.uniqueName(i)]['protocols'] = if_traffic

			if (len(topic) == 0 or topic.lower() == "ip"):
				# IP packets and breadcrumb
				rs = interface.tcpStats(i) 
				total = rs.pop('total',sum(rs.values()))
				ip_tcp = { "metadata": { "type":"piechart", "title":"TCP Statistics", "unit": "bytes", "mode" : "counter", "total": total }, "data" : rs }

				rs = interface.udpStats(i) 
				total = rs.pop('total',sum(rs.values()))
				ip_udp = { "metadata": { "type":"piechart", "title":"UDP Statistics", "unit": "bytes", "mode" : "counter", "total": total}, "data" :  rs }
			
				rs = interface.icmpStats(i)
				total = rs.pop('total',sum(rs.values()))
				ip_icmp = { "metadata": { "type":"piechart", "title":"ICMP Statistics", "unit": "bytes", "mode" : "counter", "total": total}, "data" :  rs }
			
				rs = interface.ipStats(i)
				total = rs.pop('total',sum(rs.values()))
				ip_v4v6 = { "metadata": { "type":"piechart", "title":"IP Statistics", "unit": "bytes", "mode" : "counter", "total": total}, "data" :  rs }

				ip = [ip_v4v6, ip_tcp, ip_udp, ip_icmp]
				
				rsp[interface.uniqueName(i)]['ip'] = ip
				

except Exception as inst:
    print type(inst)     # the exception instance
    print inst.args      # arguments stored in .args
    print inst           # __str__ allows args to printed directly

data = {}

if (ifname in rsp):
	
	data = rsp.get(ifname)
	
	if (len(topic) > 0):
		
		if (topic in data):
			data = {topic: data.get(topic)}
		else:
			data = {}

ntop.sendHTTPHeader(1) # 1 = HTML    
ntop.sendString(json.dumps(data, sort_keys=False, indent=4))