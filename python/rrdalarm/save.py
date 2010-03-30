'''
Created on 17/gen/2010

@author: Gianluca Medici
'''
import json
import ntop
import host
import os, os.path
import sys

import glob
# Import modules for CGI handling
import cgi, cgitb

# Fix encoding
#reload(sys)
#sys.setdefaultencoding("latin1")

''' Check if the parameter passed contains unwanted characters and returns
    a correct filename format '''
def checkFileName(fileName):
    fileName=fileName.replace(' ', '')
    fileName=fileName.replace('/', '')
    fileName=fileName.replace('\\', '')
    while(fileName.startswith('.')):
        fileName=fileName[1:]
    return fileName

''' Convert a list of any element into a string of element separated by
    separator terminating with \n'''
def _stringyfy(listVal, separator):
    returnValue=''
    for x in listVal:
        returnValue=returnValue+str(x)+separator
    
    return returnValue[0:-1]+'\n'

'''HERE STARTS THE SCRIPT'''
#import pprint
#if os.getenv('REQUEST_METHOD', 'GET') == 'POST':                          #the get method is discarded. only POST
    
cgitb.enable()

form = cgi.FieldStorage()

form.type='application/jsonrequest'
pathConfigFile=ntop.getSpoolPath()+os.sep
nameFileConfig='rrdAlarmConfig.txt'              #default nameFileConfig
#print>>sys.stderr , nameFileConfig
jsonData=form.getvalue('jsonString', '{"rows":None}')                 #get the data from the body of the post request
userConfigFile=form.getfirst('configFile', None)
#pprint.pprint(form.getvalue('configFile', None), sys.stderr)
#print>>sys.stderr, userConfigFile
if userConfigFile is not None:
    
    nameFileConfig=checkFileName(str(userConfigFile))

#pprint.pprint(nameFileConfig, sys.stderr)
#call ntop method to get post data. parse the json variable and store
configData=json.loads(jsonData,'latin1')

rows=configData['rows']
if rows is not None:
    try:
        cFile= open(os.path.join(pathConfigFile,nameFileConfig), 'w')
        cFile.write("#rrdAlarmConfig File. All the lines that starts with the '#' will be ignored! (just like this one)\n")
        for line in rows:   #save lines on cgFile. separator \t endofline \n
            #pprint.pprint(line)
            #pprint.pprint(sum(line, []))
            cFile.write( _stringyfy(line, '\t'))
        cFile.close()
        
    except IOError:
        #ntop.sendString(exceptions.html_error_template().render()) TODO
        print>>sys.stderr, "IOEXCEPTION writing file "+os.path.join(pathConfigFile,nameFileConfig)
        ack='Problems writing file <b>'+os.path.join(pathConfigFile,nameFileConfig)+'</b> operation aborted.'
        #cgi.escape(ack, True)
        ntop.sendHTTPHeader(1)
        ntop.sendString(ack)
    
    ack='Configuration file <b>'+os.path.join(pathConfigFile,nameFileConfig)+'</b> successfully saved.'
    #cgi.escape(ack, True)
    ntop.sendHTTPHeader(1)
    ntop.sendString(ack)
    print>>sys.stderr, "RRDAlarm configuration file: "+os.path.join(pathConfigFile,nameFileConfig)+" Saved "
#else: #called by a some other method rather than POST return not implemented
#    ntop.returnHTTPnotImplemented()
