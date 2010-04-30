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

ifnames = []

try:
	for i in range(interface.numInterfaces()):
		ifnames.append(interface.name(i))

except Exception as inst:
    print type(inst)     # the exception instance
    print inst.args      # arguments stored in .args
    print inst           # __str__ allows args to printed directly

ntop.sendHTTPHeader(1) # 1 = HTML
ntop.sendString(json.dumps(ifnames, sort_keys=True, indent=4))