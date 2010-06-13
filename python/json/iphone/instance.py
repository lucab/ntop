import ntop
import json
import host
import interface
# Import modules for CGI handling
import cgi
import sys

# form management
form = cgi.FieldStorage()

#instance.py?query=check&client='iphone'&version=<version>
# what king of query?
query = form.getvalue('query', default="")

# What type of client?
client = form.getvalue('client', default="")

# What version of client?
version = form.getvalue('version', default=0)
version = float(version)

data={}
if ('check' == query.lower()):
	data['check'] = version >= 1.0 and client.lower() == "iphone"

if ('interfaces' == query.lower()):
	interfaces = []
	for i in range(interface.numInterfaces()):
		interfaces.append(interface.uniqueName(i))
	data['interfaces'] = interfaces
if ('host' == query.lower()):
	data['host'] = {'version': ntop.version(),'os': ntop.os(),'uptime': ntop.uptime()}

ntop.sendHTTPHeader(1) # 1 = HTML
ntop.sendString(json.dumps(data, sort_keys=False, indent=4))
