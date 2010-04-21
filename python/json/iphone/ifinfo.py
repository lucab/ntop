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
#rsp['python_modules'] = os.listdir("python/json/iphone")

#for module in rsp['python_modules']:
#    if((module[0] == '.') or (module[len(module)-1] == '~')):
#        rsp['python_modules'].remove(module)

ntop.sendHTTPHeader(1) # 1 = HTTP
ntop.sendString("<pre>")
ntop.sendString(json.dumps(rsp, sort_keys=False, indent=4))
ntop.sendString("</pre>")