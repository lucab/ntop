import ntop
import fastbit
#import pprint

# Import modules for CGI handling
import cgi, cgitb
import socket, struct, sys, glob

exceptions_so_far = 0

try:
    import json
except:
    ntop.printHTMLHeader('ntop Python Configuration Error', 1, 1)
    ntop.sendString("<b><center><font color=red>Please install JSON support in python</font><p></b><br>E.g. 'sudo apt-get install python-json' (on Debian-like systems)</font></center>")
    ntop.printHTMLFooter()    
    exceptions_so_far=1

# Parse URL
cgitb.enable();

import re, os, os.path
from StringIO import StringIO

'''
return a list of directories representing tables for fastbit, as long as the list to be returned is  len() ==1
iterate to get more results (if possible)
'''
def expandTables(string, pathFastbitDir):
    directoryList=[]
    
    try:
        tempList=None
        #tempList = glob.glob(os.path.join(pathFastbitDir, string)+'*')
        while not tempList or len(tempList)==1:
            tempList = glob.glob(os.path.join(pathFastbitDir, string)+'*')
            
            if tempList and len(tempList)==1: #if found just one result
                string=tempList[0][len(pathFastbitDir):]+os.sep
            else: #more than one results stops the cicle
                break
        
        if tempList:
            directoryList=tempList
        else:
            return []
    except:
        raise
        return []
    retList=[]
    for file in directoryList:
        #filePath=os.path.join(pathFastbitDir,file)
        #remove all the files in the fastbit directory that are not a directory or of witch I don't have read privileges
        if os.path.isdir(file) and not os.path.islink(file) and os.access(file, os.R_OK):
            retList.append(file[len(pathFastbitDir):])
    if len(retList) <=0 and len(directoryList)>0: #if no directory was found take the father
        
        tmpDir=os.path.dirname(directoryList[0])
        if tmpDir!=pathFastbitDir:
            retList.append(tmpDir[len(pathFastbitDir):])
    else:
        retList.sort()
    return retList

'''
def expandTablesOLD(string, pathFastbitDir):
    directoryList=[]
    
    try:
        tempList=None
        while not tempList or len(tempList)==1:
            tempList = glob.glob(os.path.join(pathFastbitDir, string)+'*')
            
            if tempList and len(tempList)==1:
                string=tempList[0]+os.sep
            else:
                break
        
        if tempList:
            directoryList=tempList
        else:
            return []
    except:
        raise
        return []
    retList=[]
    for file in directoryList:
        #filePath=os.path.join(pathFastbitDir,file)
        #remove all the files in the fastbit directory that are not a directory or of witch I don't have read privileges
        if os.path.isdir(file) and not os.path.islink(file) and os.access(file, os.R_OK):
            retList.append(file[len(pathFastbitDir):])
    if len(retList) <=0 and len(directoryList)>0: #if no directory was found take the father
        
        tmpDir=os.path.dirname(directoryList[0])
        if tmpDir!=pathFastbitDir:
            retList.append(tmpDir[len(pathFastbitDir):])
    else:
        retList.sort()
    return retList
'''

'''Return a json object for the from field autocomplete'''
def expandFrom(fromArg, pathFastBit):
    jsonList={'results':[]}
    fromArg=fromArg.rstrip()        #remove the white spaces at the end
    fromArg=fromArg.upper()
    results=[]
    if(fromArg[-1]== ','):          #autocomplete only for trailing , in the select
        
        listDirs=expandTables('', pathFastBit)
        i=0
        for dir in listDirs:
                n=fromArg+' '+dir
                results.append({'id': i , 'value':n}) #building a list of expanded table field
                i=i+1
    else:
        lastArg=fromArg
        ind=fromArg.rfind(',')
        if ind != -1:               #there are other columns before
            lastArg=fromArg[ind+1:]
        listDirs=expandTables(lastArg, pathFastBit)
        i=0
        for dir in listDirs:
            if ind!= -1:            #concatenate with the table before
                n=fromArg[0:ind]+' '+dir
                results.append({'id': i , 'value':n})
            else:
                                    #first table just list the results
                results.append({'id': i , 'value':dir})
            i=i+1
    jsonList['results']=results
    
    #pprint.pprint(results, sys.stderr)
    return json.dumps(jsonList)

'''Return a descriptive string from (some of) the protocols code defined in in.h'''
def getNameByProto(numberProtocol):
    if numberProtocol == 1:
        return "ICMP"
    elif numberProtocol == 2:
        return "IGMP"
    elif numberProtocol == 6:
        return "TCP"
    elif numberProtocol == 17:
        return "UDP"
    else:
        return "UNK"

''' Convert the number passed to a ip string in dotted notation, work for both ipv4 an ipv6. 
    Raise an exception if failed conversion'''
def numberToIp(number):
    try:
        #just ipv4
        return socket.inet_ntop(socket.AF_INET, struct.pack('>L',number))
    except:
        #could be an ipv6
        try:
            return socket.inet_ntop(socket.AF_INET6, struct.pack('>L',number))
        except:
            #failed ipv6 and ipv4 conversion
            print>>sys.stderr, "ipPortQuery.py: IMPOSSIBLE TO FORMAT value: "+str(number)+" TO IP ADDR"
            raise
''' Convert the ip string passed in dotted notation (just ipv4)  to a number representing in the ip in 
    network order '''
def ipToNumber(ipString):
    try:
        #just ipv4
        return struct.unpack('>L', socket.inet_pton(socket.AF_INET,ipString))[0]
    except:
        print>>sys.stderr, "ipPortQuery.py: IMPOSSIBLE TO FORMAT input IP : "+str(ipString)+" TO int"
        raise
        #could be an ipv6
        '''try:
            return struct.unpack('>L', socket.inet_pton(socket.AF_INET6,ipString))[0]
        except:
            print>>sys.stderr, "ipPortQuery.py: IMPOSSIBLE TO FORMAT input IP : "+str(ipString)+" TO int"
            raise'''
    
'''
returns the first subdirectory with no subdirectory, leftmost.
usefull to get a dumped fastbit directory
'''
def getFirstDirWithNoDir(path):
    allTheFiles=os.listdir(path)
    if not allTheFiles or type(allTheFiles)!=list:
        return None
    #allTheFiles.sort()        #to take the first dir in lexicographic order
    firstDir=None
    for file in allTheFiles:
        filePath=os.path.join(path,file)
        if os.path.isdir(filePath) and os.access(filePath, os.R_OK):
            temp =getFirstDirWithNoDir(filePath+os.sep)
            if temp is None:
                return filePath
            else: 
                return temp;
    else:
        return None

'''
Remove all the spaces an split at the , the string passed
the list returned is a list of positions (integer) of splitted strings ending with ADDR or MASK
'''
def getAddrCols(string):
    ipType=re.compile(r'.+(ADDR|MASK)$')
    i=0
    toFormat=[]
    for c in string.replace(' ', '').split(','):
        if ipType.match(c):
            toFormat.append(i)
        i=i+1
    return toFormat

def begin():
    # Imports for mako
    try:
        from mako.template import Template
        from mako.runtime import Context
        from mako.lookup import TemplateLookup
        from mako import exceptions
    except:
        ntop.printHTMLHeader('ntop Python Configuration Error', 1, 1)
        ntop.sendString("<b><center><font color=red>Please install <A HREF=http://www.makotemplates.org/>Mako</A> template engine</font><p></b><br>(1) 'sudo yum install python-setuptools' (on RedHat-like systems)<br>(2) 'sudo easy_install Mako'</font></center>")
        ntop.printHTMLFooter()
        return
    # Fix encoding
    #reload(sys)
    #sys.setdefaultencoding("latin1")
    
    templateFilename='ipPortQuery.tmpl'
    
    #fb_DB = '/tmp/'               #ntop.getPreference ("fastbitDBPath");    #default location of the fastbit DB
    databasePath = ntop.getPreference ("fastbit.DBPath");    #default location of the fastbit DB
        
    if databasePath is None or databasePath=='':
        ntop.printHTMLHeader('ntop Fastbit Configuration Error', 1, 1)
        ntop.sendString("<b><center><font color=red>Please set fastbit.DBPath ntop preferences from <i>Admin/Configure/Preferences</i> menu (es: fastbit.DBPath=/tmp/)</b></font></center>")
        ntop.printHTMLFooter()
        return
    
    #pathFastBit=os.path.join(databasePath,'fastbit'+os.path.sep)
        
    
    form = cgi.FieldStorage();                      #get from the url the parameter configfile that contains the 
                                                    #path+filename of the configfile to read
    fromAuto=form.getvalue('fromAuto')
    
    if fromAuto:
        #print>>sys.stderr, "AJAX REQUEST FOR PARTITION IN  "+databasePath+" "+fromAuto
        jsonString=expandFrom(fromAuto, os.path.join(databasePath, "") )
        ntop.sendHTTPHeader(12)
        ntop.sendString(jsonString)
        return
    
    
    documentRoot=os.getenv('DOCUMENT_ROOT', '.')
    
    selectArg='PROTOCOL,IPV4_SRC_ADDR,L4_SRC_PORT,IPV4_DST_ADDR,L4_DST_PORT,IN_BYTES,IN_PKTS'
    fromArg=form.getvalue('partition')
    
    ipSrc=form.getvalue('ipSrc')
    ipDst=form.getvalue('ipDst')
        
    
    portSrc=form.getvalue('portSrc')
    portDst=form.getvalue('portDst')
    
    limit = int(form.getvalue('limit', 100))
    
    if limit<0: 
        limit=0
    res=None                #variable to store the results of the query   
    ntop.printHTMLHeader('IP-Port Query', 1, 0)
    #regex to check passed parameters
    ipV4Type=re.compile(r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
    portType=re.compile(r'\d{1,5}')
    
    #pprint.pprint(ipV4Type.match(str(ipSrc)), sys.stderr)
    formatErrorString=''
    #without the partition do nothing
    if fromArg :
        whereArg='1=1'      #to avoid leaving the where clause empty
        if ipSrc:
            #print>>sys.stderr, 'ECCO '+str(ipV4Type.match(ipSrc))
            if ipV4Type.match(ipSrc):
                whereArg=whereArg+' AND IPV4_SRC_ADDR='+str(ipToNumber(ipSrc))
            else:
                formatErrorString=formatErrorString+'Source ip format invalid! ipv4 format required. '
        if portSrc:
            if portType.match(portSrc):
                whereArg=whereArg+' AND L4_SRC_PORT='+str(portSrc)
            else:
                formatErrorString=formatErrorString+'Source Port format invalid! Number required. '
        if ipDst:
            if ipV4Type.match(ipDst):
                whereArg=whereArg+' AND IPV4_DST_ADDR='+str(ipToNumber(ipDst))
            else:
                formatErrorString=formatErrorString+'Destination ip format invalid! ipv4 format required. '
        if portDst:
            if portType.match(portDst):
                whereArg=whereArg+' AND L4_DST_PORT='+str(portDst)
            else:
                formatErrorString=formatErrorString+'Destination Port format invalid! Number required. '
        try:
            #pipe = subprocess.Popen (['ntop.getPreference ("fastbit.fbquery")', "-c", selectArg, "-d", fromArg, "-q", whereArg, "-P", "-L", limit],
            #print>>sys.stderr, "Query passed: SELECT %s FROM %s WHERE %s LIMIT %i" %(selectArg,os.path.join(databasePath, fromArg),  whereArg, limit)
            if formatErrorString=='':
                res = fastbit.query(os.path.join(databasePath, fromArg), selectArg, whereArg, limit)
            else:
                print>>sys.stderr, 'ipPortQuery: ERROR '+formatErrorString
                ntop.sendString('<center><font color=red>%s</font></center>'%formatErrorString)
            #print>>sys.stderr, 'Number of records: %i' % len(res['values'])
        except:
            print>>sys.stderr, 'ERROR Executing query: '+("SELECT %s FROM %s WHERE %s LIMIT %i" %(selectArg,os.path.join(databasePath, fromArg),  whereArg, limit))
            res = {}
        if res is not None and 'columns' in res and 'values' in res:
            
            toFormat=getAddrCols(selectArg)         #get a list of addr column numbers
            
            for x in res['values']:
                x[0]=getNameByProto(x[0])           #format protocol number to text
                for j in toFormat:
                    #for every number in the list format as an IP ADDR
                    ipStr=numberToIp(x[j])
                    x[j]='<a href="/%s.html" class="tooltip">%s</a>' % (ipStr,ipStr)   #format ip number to string ip and create a link to ntop host page 
    '''else:
        print>>sys.stderr, 'ipPortQuery: ERROR partition required'
        ntop.sendString('<center><font color=red>Partition field required!</font></center>')'''
    #pprint.pprint(res, sys.stderr)
    #if res is not None:
    #    res['columns']=['Protocol', 'IP Source Addr', 'IP Dest. Addr', 'Source Port', 'Dest. Port', 'Bytes Rcvd', 'Packets Rcvd']
    
    try:
        basedir =  os.path.join(documentRoot,'python/templates')
        mylookup = TemplateLookup(directories=[basedir])
        myTemplate = mylookup.get_template(templateFilename)
        buf = StringIO()
        
        ctx = Context(buf, results=res)
        
        myTemplate.render_context(ctx)
        ntop.sendString(buf.getvalue())
    except:
        ntop.sendString(exceptions.html_error_template().render())
    
    ntop.printHTMLFooter()
    

'''HERE STARTS THE SCRIPTS'''
if exceptions_so_far == 0:
    begin()