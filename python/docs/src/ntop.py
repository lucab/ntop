"""
Module that provides basic function to interact to the ntop http server and to get info on the ntop state.

Others exposed functions allows to cycle through all the hosts currently monitored by ntop.
 
"""

def sendHTTPHeader(mime_type):
    """
    send an header back to the client
    @type mime_type: int
    @param mime_type: the mime type of the http respons (check global-defines.h for defined types. ES. 1 for html 12 for json)
    """
    pass
def returnHTTPnotImplemented():
    """
    send http message code 501  back to the client
    """
    pass
def returnHTTPversionServerError():
    """
    send http message code 500  back to the client
    """
    pass
def printHTMLHeader(title, sectionTitle, refresh):
    """
    print the standard ntop header opening an html page to be filled with data
    @type title:  string
    @param title: the title of the page
    @type sectionTitle: int 0 false 1 true
    @param sectionTitle:  flag that indicates if the print should stop just before the sectionTitle of the page (no title will be printed)
    @type refresh: int 0 false 1 true
    @param refresh: flag to inhibit the refresh for the current generated html page
    """
    pass
def printHTMLFooter():
    """
    print the standard ntop footer closing an html page
    """
    pass

def sendString(msg):
    """
    send back to the client the message passed 
    @type msg: string
    @param msg: the message to be printed back to the client
    """
    pass

def printFlagedWarning(msg):
    """
    print a warning message and an image to instruct the users about the problem encountered 
    @type msg: string
    @param msg: the message to print
    """
    pass

def getFirstHost(actualDeviceId):
    """
    retrieve the first host of the list of hosts currently monitored by ntop
    @type actualDeviceId: int
    @param actualDeviceId: the number of the device from witch get the list of hosts, None to get from all interfaces
    @rtype: int
    @return: 1 indicates that the first host was found, 0 otherwise
    """
    pass
def getNextHost(actualDeviceId):
    """
    retrieve the next host of the list of hosts currently monitored by ntop
    if no first host was previously retrieved get the first host of the list
    @type actualDeviceId: int
    @param actualDeviceId: the number of the device from witch get the list of hosts, None to get from all interfaces
    @rtype: int
    @return: 1 indicates that the next host was found, 0 otherwise
    """
    pass
def findHostByNumIP(hostIpAddress, vlanId, actualDeviceId):
    """
    retrieve the host corresponding to the parameters passed (if any)
    @type hostIpAddress: string
    @param hostIpAddress: the ip address in dotted notation for ipv4 or string notation for ipv6
    @type vlanId: int
    @param vlanId: the number representing the vlanId in witch to search for the ipAddress passed
    @type actualDeviceId: int
    @param actualDeviceId: the number of the device from witch get the list of hosts, None to get from all interfaces
    @return: 1 indicates that the host was found, 0 otherwise
    """
    pass

def version():
    """
    retrieve the version of this ntop release
    @rtype: string
    @return the current version of ntop
    """
    pass
def os():
    """
    retrieve the operative system in witch ntop was build
    @rtype: string
    @return the name of the OS
    """
    pass

def uptime():
    """
    the current uptime of ntop
    @rtype: string
    @return the time from witch ntop started sniffing
    """
    pass

def getPreference(key):
    """
    get the ntop preference named key
    @type key: string
    @param key: the name of the preference from witch get the value
    @rtype:  string or None
    @return: the value of the preference set in ntop if any, null otherwise
    """
    pass

def setPreference( key, value):
    """
    set a preference in ntop, as if the user insert a new preference in the html interface
    @type key: string
    @param key: the key of the preference to set
    @type value: string
    @param value: the value to associate to the key passed
    """
    pass

def getDBPath():
    """
    get the current dbPath defined in ntop
    @rtype: string
    @return: the db path defined in ntop
    """
def getSpoolPath():
    """
    get the current spoolPath defined in ntop
    @rtype: string
    @return: the spool path defined in ntop
    """
    pass

def updateRRDCounter(path, key, value, step):
    """
    update the counter of the RRDDatabase (specified by path and key) with the value passed
    @type path: string
    @type key: string
    @type value: number
    @type step: int
    @rtype: int
    @return: int on success, -1 on failure
    """
    pass
def updateRRDGauge(path, key, value, step):
    """
    update the gauge of the RRDDatabase (specified by path and key) with the value passed
    @type path: string
    @type key: string
    @type value: number
    @type step: int
    @rtype: int
    @return: int on success, -1 on failure
    """
    pass

def rrd_fetch(pathFilename, function, start, end):
    """
    fetch data from the pathFilename RRA acrhive pecified
    @type pathFilename: string
    @param pathFilename: the path and filename of the RRA from witch to fetch data
    @type function: string
    @param function: the name of the consolidation function to use (AVERAGE, MIN, MAX, LAST)
    @type start: string
    @param start: the start time from witch to fetch
    @type end: string
    @param end: the end time to stop fetching
    @rtype : tuple ((start, end, step), (name1, name2, ...), [(data1, data2, ..), ...])
    @return the tuple containing the values fetched from the RRA pathFilename passed, on failure rrdtool.error exception is raised 
    """
    pass
