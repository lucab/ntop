import ntop
import interface
import json

rsp = {}

#try:
for i in range(interface.numInterfaces()):
        info = {}
        info['name'] = interface.name(i)
        info['humanName'] = interface.humanName(i)
        info['time'] = interface.time(i)
        info['virtual'] = interface.virtual(i)
        info['speed'] = interface.speed(i)
        info['mtu'] = interface.mtu(i)
        info['bpf'] = interface.bpf(i)

	addr = {}
        addr['ipv4'] = interface.ipv4(i)
        addr['network'] = interface.network(i)
        addr['numHosts'] = interface.numHosts(i)
	addr['ipv6'] = interface.ipv6(i)
	info['address'] = addr

	stats = {}
        stats['pktsStats'] = interface.pktsStats(i)
        stats['bytesStats'] = interface.bytesStats(i)
        stats['throughputStats'] = interface.throughputStats(i)
	
	ip = {}
        ip['tcp'] = interface.tcpStats(i)
        ip['udp'] = interface.udpStats(i)
        ip['icmp'] = interface.icmpStats(i)
        ip['ip'] = interface.ipStats(i)

        stats['securityPkts'] = interface.securityPkts(i)	
	stats['netflowStats'] = interface.netflowStats(i)
	stats['sflowStats'] = interface.sflowStats(i)
	stats['cpacketStats'] = interface.cpacketStats(i)
	stats['ip'] = ip
	info['stats'] = stats

        rsp[interface.uniqueName(i)] = info

#except Exception as inst:
#    print type(inst)     # the exception instance
#    print inst.args      # arguments stored in .args
#    print inst           # __str__ allows args to printed directly
    
ntop.sendString(json.dumps(rsp, sort_keys=True, indent=4))

