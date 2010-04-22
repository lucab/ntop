#
# (C) 2010 -David Votino
#
import ntop
import interface
import json

rsp = {}

rsp['version'] = ntop.version();
rsp['os'] = ntop.os();
rsp['uptime'] = ntop.uptime();

ntop.sendHTTPHeader(1) # 1 = HTTP
ntop.sendString(json.dumps(rsp, sort_keys=False, indent=4))