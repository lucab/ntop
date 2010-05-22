'''
Created on 16/gen/2010

@author: Gianluca Medici
'''
import ntop
import host
import os, os.path
import sys
#import pprint
import glob

exceptions_so_far = 0

try:
    import json
except:
    ntop.printHTMLHeader('ntop Python Configuration Error', 1, 1)
    ntop.sendString("<b><center><font color=red>Please install JSON support in python</font><p></b><br>E.g. 'sudo apt-get install python-json' (on Debian-like systems)</font></center>")
    ntop.printHTMLFooter()    
    exceptions_so_far=1

# Import modules for CGI handling
import cgi, cgitb

from StringIO import StringIO
#return a json string of filenames from the path expanded with a *, if the result is just one and is a directory it continues the search inside it 
def jsonListFileInPath(path, ntopSuffix):
    jsonList={'results':[]}
    
    listFile = glob.glob(os.path.join(ntopSuffix,path)+'*')   #expand the * and ? into a list of files
    i=1
    if len(listFile)==1 and os.path.isdir(listFile[0]):
        listFile=listFile+glob.glob(os.path.join(listFile[0],'*'))
        #pprint.pprint(listFile, sys.stderr)
    
    for file in listFile:
        if os.path.isdir(file):
           file=file+os.sep
        
        #print>>sys.stderr, file
        file=file[len(ntopSuffix):]
        jsonList['results'].append({'id': i , 'value':file})
    return json.dumps(jsonList)
        
def listAllDirs(dirPath):
    arr=[]
    #pprint.pprint(os.listdir(dirPath),sys.stderr) 
    for file in os.listdir(dirPath):
        newPath=os.path.join(dirPath,file)
        if os.path.isdir(newPath) : 
            #return [newPath]+listAllDirs(newPath)
            #print>>sys.stderr, file
            arr.append(newPath+os.sep);
            arr=arr+listAllDirs(newPath+os.sep)
    return arr
    
''' Function that provide a list of names of the scripts .py present in the scripts directory
    the list returned does not contain the name of this module as well as the name of the __init__
    module. The names provided in the returned list will be lacking of the trailing .py
'''
def readScriptsDir(pathScriptsDir):
    import sys
    import glob
    directoryList=[]
    try:
        directoryList = glob.glob1(pathScriptsDir, '*')
    except:
        raise
        return ['None']
    
    nameScriptList=['None']
    for scriptName in directoryList:
        if os.access(os.path.join(pathScriptsDir,scriptName), os.X_OK) or scriptName[-3:]=='.py':
            justName=scriptName.partition('.')[0]
            if justName and len(justName)>0:
                nameScriptList.append(justName)             #remove the last 3 characters .py from the name of the script
    
    return nameScriptList

def begin():
    
    templateFilename='rrdAlarmConfigurator.tmpl'
    # Imports for mako
    try:
        from mako.template import Template
        from mako.runtime import Context
        from mako.lookup import TemplateLookup
        from mako import exceptions
    except:
        ntop.printHTMLHeader('ntop Python Configuration Error',1,0)
        ntop.sendString("<b><center><font color=red>Please install <A HREF=http://www.makotemplates.org/>Mako</A> template engine</font> (sudo easy_install Mako)</center></b>")
        ntop.printHTMLFooter()    
        return
    
    # Fix encoding
    #reload(sys)
    #sys.setdefaultencoding("latin1")
    
    
    rows=[]
    pathRRDFiles=os.path.join(ntop.getDBPath(),'rrd/')
    nameFileConfig='rrdAlarmConfig.txt'              #default nameFileConfig
    pathTempFile=ntop.getSpoolPath()+os.sep
    
    
    form = cgi.FieldStorage();                      #get  from the url the parameter configfile that contains the 
                                                    #path+filename of the configfile to read
    jsonPathRRD=form.getvalue('pathRRDS')
    
    
    help=form.getvalue('help')
    documentRoot=os.getenv('DOCUMENT_ROOT', '.')
    
    if jsonPathRRD:
        #a request from the autocomplete script, return a json string with the matching files names
        ntop.sendHTTPHeader(1)
        ntop.sendString(jsonListFileInPath(jsonPathRRD, pathRRDFiles))
        return
    elif help == 'true':
        #show help page
        templateFilename='rrdAlarmConfiguratorHelp.tmpl'
        ntop.printHTMLHeader('RRD Alarm Configurator Help', 1, 0)
    else:
        #normal operation
        requestFileConfig=form.getvalue('configFile')
        if requestFileConfig is not None:
            nameFileConfig=requestFileConfig
        
        #get all the scripts in the scripts directory
        listScripts=readScriptsDir(os.path.join(documentRoot,'python/rrdalarm/scripts/'))
        
        ntop.printHTMLHeader('RRD Alarm Configurator', 1, 0)
        
        file_name = os.path.join(pathTempFile,nameFileConfig)
        
        try:    
            configFile= open(file_name, 'rt')
            
            for line in configFile:
                line=line.rstrip()                      #drop the \n at the end
                if len(line) >0 and line[0] != '#':
                    rows.append(line.split('\t'))
            
            configFile.close()
            
        except IOError:
            try:
                open(file_name, 'w').close()  # Create an empty file if missing
            except:
                pass
            print>>sys.stderr, "RRDAlarm: empty configFile created "+file_name
        except:
            print>>sys.stderr, "RRDAlarm: Error reading configFile "+os.path.join(pathTempFile,nameFileConfig)
            raise
        #the elaboration will continue but no data will be displayed.
        
            #if requestFileConfig is not None:                 #if the nameFileConfig was specified by user show error
            #try:
            #    open(os.path.join(pathTempFile,nameFileConfig), 'w')
            #except:
            #    raise
            #else:
            #nameFileConfig='rrdAlarmConfig.txt'
            #ntop.sendString(exceptions.html_error_template().render())
    
    try:
        #pprint.pprint(listAllDirs(pathRRDFiles+'rrd/'), sys.stderr)
        basedir =  os.path.join(documentRoot,'python/templates')
        mylookup = TemplateLookup(directories=[basedir])
        myTemplate = mylookup.get_template(templateFilename)
        buf = StringIO()
        ctx=None
        if(help =='true'):          #show help page
            ctx = Context(buf)
        else:
            ctx = Context(buf, configRows=rows,tempFilePath=pathTempFile, nameFileConfig=nameFileConfig,listScripts=listScripts,  pathRRDFiles=pathRRDFiles)  #, rrdDirs=listAllDirs(pathRRDFiles+'rrd/')
        
        myTemplate.render_context(ctx)
        ntop.sendString(buf.getvalue())
    except:
        ntop.sendString(exceptions.html_error_template().render())
    
    ntop.printHTMLFooter()


'''Here starts the script'''

if exceptions_so_far == 0:
    begin()
