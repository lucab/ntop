#!/usr/bin/env python

import urllib, time

URL = "http://localhost:3000/dumpData.html?language=python"

print "Getting NTop stats in Python format"
statsText = ''
attempt = 1
# NTop takes a while to build the stats
while not statsText.count("hostNumIpAddress"):
	print "Attempt #" + str(attempt)
	try:
		statsText = urllib.urlopen(URL).read()
	except IOError:
		"NTop timed out, is it active?"
	assert statsText.count("ntopDict"), \
		"ntopDict not in output"
	assert attempt < 100, \
		"Could not get stats from NTop"
	attempt += 1
	# give it a little while
	time.sleep(2)
try:
	exec(statsText)
except:
	print "Problems interpreting the stats"
else:
	print "Found stats for the following hosts:"
	for host in ntopDict.keys():
		print host
print "All done."
