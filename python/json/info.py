#
# (C) 2010 - Luca Deri
#
import ntop
import interface
import json

rsp = {}

rsp['version'] = ntop.version();
rsp['os'] = ntop.os();
rsp['uptime'] = ntop.uptime();
rsp['python_modules'] = os.listdir("python/json")

for module in rsp['python_modules']:
    if((module[0] == '.') or (module[len(module)-1] == '~')):
        rsp['python_modules'].remove(module)

ntop.sendHTTPHeader(12) # 12 = JSON
ntop.sendString(json.dumps(rsp, sort_keys=True, indent=4))
