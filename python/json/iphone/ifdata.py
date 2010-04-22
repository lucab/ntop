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
			info['info'] = if_info

			# add time info to interface data
			info['time'] = interface.time(i)

			# Interface address info
			if_addr = {}
			if_addr['ipv4'] = interface.ipv4(i)
			if_addr['network'] = interface.network(i)
			if_addr['numHosts'] = interface.numHosts(i)
			if_addr['ipv6'] = interface.ipv6(i)

			# Add address info to interface data
			info['address'] = if_addr
			
			ifdata = [{"data" : info, "metadata" : info_metadata}]
			
			# Statistics of the interface traffic
			rs = interface.pktsStats(i)
			total = rs.pop('total',sum(rs.values()))
			pktsStats = { "metadata": { "type":"barchart", "title":"Packet Statistics", "unit": "packets", "mode" : "counter", "total": total }, "data" : rs }
			
			rs = interface.bytesStats(i)
			total = rs.pop('total',sum(rs.values()))
			bytesStats = { "metadata": { "type":"piechart", "title":"Bytes Statistics", "unit": "bytes", "mode" : "counter", "total": total }, "data" : rs }

			rs = interface.throughputStats(i)
			total = rs.pop('total',sum(rs.values()))
			throughputStats = { "metadata": { "type":"table", "title":"Throughput Statistics", "unit": "bytes/sec", "mode" : "gauge", "total": total }, "data" : rs }
			
			rs = interface.securityPkts(i)
			total = rs.pop('total',sum(rs.values()))
			securityPkts = { "metadata": { "type":"barchart", "title":"Security Packet Statistics", "unit": "packets", "mode" : "counter", "total": total}, "data" : rs }
			# Build traffic info for interface
			if_traffic = [pktsStats, bytesStats, securityPkts, throughputStats]

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

			#info['ip'] = ip

			rsp[interface.uniqueName(i)] = { "interface" : ifdata, "protocols" : if_traffic, "ip" : ip}

except Exception as inst:
    print type(inst)     # the exception instance
    print inst.args      # arguments stored in .args
    print inst           # __str__ allows args to printed directly

data = {}

if (ifname in rsp):
	
	data = rsp.get(ifname)
	
	if (len(topic) > 0):
		
		if (topic in data):
			data = data.get(topic)
		else:
			data = {}

ntop.sendHTTPHeader(1) # 1 = HTML    
ntop.sendString("<pre>")
ntop.sendString(json.dumps(data, sort_keys=False, indent=4))
ntop.sendString("</pre>")
