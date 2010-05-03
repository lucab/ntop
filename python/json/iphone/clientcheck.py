#
# (C) 2010 -David Votino
#
# Just checks the client version against
# the current allowed client
# returns 1 if ok, 0 if not ok
# also checks client type for when we'll have ipad support 
# or a specific device support ( android ? )
#
import json
import cgi
import ntop

# allows client version 1 as of release date.
# will refuse clients with versions below this one.
# IPHONE
__MINIPHONEALLOWEDCLIENTVERSION__ = 1.0

__IPHONECLIENTTYPE__ = 'iphone'

# form management
form = cgi.FieldStorage();

# How many top hosts?
version = form.getvalue('version', default=0)
version = float(version)

clientType = form.getvalue('type', default='')
clientType = clientType.lower()

allowed = 0

if __IPHONECLIENTTYPE__ == clientType and __MINIPHONEALLOWEDCLIENTVERSION__ <= version:
	allowed = 1

ntop.sendHTTPHeader(1) # 1 = HTTP
ntop.sendString(json.dumps({"allowed":allowed}, sort_keys=False, indent=4))