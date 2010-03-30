# coding: utf-8
import ntop
import fastbit
#import pprint

# Import modules for CGI handling
import cgi, cgitb
import socket, struct, sys

# Parse URL
cgitb.enable();

from StringIO import StringIO

import re, glob, os, os.path, json     #TODO check for json existence inside the function and return error if not find

import pickle

'''Not yet used'''
strSelect="select "
strFrom="from "
strWhere="where "
selectFromWhere=re.compile('(%s)(.* )(%s)(.* )(%s)(.* )' % (strSelect, strFrom, strWhere),re.I)
selectFrom=re.compile('(%s)(.* )(%s)(.* )' % (strSelect, strFrom),re.I)
select=re.compile('(%s)(.* )' % strSelect ,re.I)
#selectFrom=re.compile(r'(select )(*)(from )(*)', re.I)
#select=re.compile(r'(select )(*)', re.I)
'''end of not yet used'''


''' Function that create or replace a tempFile containing the the persistance 
    information for resuming this script status at next run '''
def saveTempFile(object, tempFileName):
    #the changes made to the configuration will be saved in tempfile
    try:
        tempFile= open(tempFileName, 'w')
        pickle.dump(object, tempFile, pickle.HIGHEST_PROTOCOL)
        tempFile.close()
    except:
        print>>sys.stderr, 'Fastbit Query: Error saving the the query history on disk!'
        return -1
    return 0
'''
return a list of directories representing tables for fastbit, as long as the list to be returned is  len() ==1
interate to get more results (if possible)
'''
def expandTables(string, pathFastbitDir):
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
        if os.path.isdir(file) and os.access(file, os.R_OK):
            retList.append(file[len(pathFastbitDir):])
    retList.sort()
    return retList

def expandTablesJustOne(string, pathFastbitDir):
    directoryList=[]
    try:
        directoryList = glob.glob1(pathFastbitDir, string+'*')
    
    except:
        raise
        return []
    
    for file in directoryList:
        filePath=os.path.join(pathFastbitDir,file)
        #remove all the files in the fastbit directory that are not a directory or of witch I don't have read privileges
        if not os.path.isdir(filePath) or not os.access(filePath, os.R_OK):
            directoryList.remove(file)
    
    return directoryList

'''
returns a list of 'columns' (files) name in the pathfastbitdirtable 
'''
def expandTableFields(string, pathFastbitDirTable):
    fieldList=[]
    try:
        fieldList = glob.glob1(pathFastbitDirTable, string+'*')
    except:
        raise
        return []
    
    for file in fieldList:
        filePath=os.path.join(pathFastbitDirTable,file)
        #remove all the files in the fastbitdirTable directory that are directory with no read privileges or with dots in the name
        if os.path.isdir(filePath) or not os.access(filePath, os.R_OK) or file.find('.')!=-1:
            fieldList.remove(file)
    return fieldList

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
            if temp==None:
                return filePath
            else: 
                return temp;
    else:
        return None
    
'''
NOT COMPLETED
the function for autocomplete a full query string including the Select from where commands
TO BE COMPLETED
'''
def expandQuery(query):
    jsonList={'results':[]}
    tmpRe=re.compile(query+'*')
    
    #autocomplete for sql ide
    if tmpRe.match('.+ '+strWhere):
        results.append({'id': 1 , 'value':query+strWhere, 'info':query+strWhere})
        return jsonList
    elif tmpRe.match('.+ '+strFrom):
        results.append({'id': 1 , 'value':query+strForm, 'info':query+strForm})
        return jsonList
    elif tmpRe.match(strSelect):
        results.append({'id': 1 , 'value':strSelect, 'info':strSelect})
        return jsonList
    
    #autocomplete for database tables and fields
    matchObj=selectFromWhere.match(query)
    if matchObj:
        #the string is almost complete the user have to set the where conditions
        selectArg=matchObj.group(0)
        selectArg=selectArg.rstrip()        #remove the white spaces at the end
        if(selectArg[-1]== ','):            #autocomplete only for trailing , in the select
            index=matchObj.end(0)
            results=[]
            listNameFields=expandTableFields('', pathFastbitDirTable)
            for fileNames in results:
                if index!=-1: 
                    results.append(query[0, index]+' '+filename+' '+query[index+1:]) #building a list of expanded table field
            jsonList['results']=results
        return jsonList   
    
    matchObj=selectFrom.match(query)
    if matchObj:
        fromArg=matchObj.group(1)
        fromArg=fromArg.rstrip()            #remove the white spaces at the end
        listTables=expandTables(fromArg, pathFastbitDir)
        index=matchObj.start(1)
        results=[]
        for tableName in listTables:
            if index!=-1:
                results.append(query[0, index]+tablename) #building a list of expanded tables name
        #populate jsonList with the tables on the fastbit directory
        jsonList['results']=results 
        return jsonList
    
    matchObj=select.match(query)
    if matchObj:
        #take the first directory in the fastbitDir and expand its fields (assumption there all the same in all the directories)
        allTheFiles=os.listdir(pathFastbit)
        firstDir=getFirstDirWithNoDir(pathFastbit)
        if firstDir !=None:#to complete
            jsonList['results']=expandTableFields(string, firstDir)
            
    
    return jsonList

'''Return a json object for the from field autocomplete'''
def expandSelect(selectArg, pathFastbit, dir):
    jsonList={'results':[]}
    if not dir:
        dir=getFirstDirWithNoDir(pathFastbit)
    else:
        dir=os.path.join(pathFastbit, dir+os.sep)
    print>>sys.stderr, dir+selectArg
    selectArg=selectArg.strip()     #remove the white spaces at the two extremes
    selectArg=selectArg.upper()
    results=[]
    if(selectArg[-1]== ','):        #autocomplete only for trailing , in the select
        
        listNameFields=expandTableFields('', dir)
        i=0
        for filename in listNameFields:
                n=selectArg+' '+filename
                results.append({'id': i , 'value':n}) #building a list of expanded table field
                i=i+1
    else:
        lastArg=selectArg
        ind=selectArg.rfind(',')
        if ind != -1:               #there are other columns before
            lastArg=selectArg[ind+1:].lstrip()
        
        listNameFields=expandTableFields(lastArg, dir)
        i=0
        for filename in listNameFields:
            if ind!= -1:            #concatenate with the columns before
                n=selectArg[0:ind+1]+' '+filename
                results.append({'id': i , 'value':n})
            else:
                                    #first column just list the results
                results.append({'id': i , 'value':filename})
            i=i+1
    jsonList['results']=results
    
    return json.dumps(jsonList)

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
    
    return json.dumps(jsonList)

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
    historyLimit=10
    templateFilename='fastbit.tmpl'
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
    reload(sys)
    sys.setdefaultencoding("latin1")
    ntopSpoolPath=ntop.getSpoolPath()
    tempQueryHistory="fbQueryHistory"
    
    rows=[]
    cols=None
    
    databasePath=ntop.getDBPath()
    
    '''TODO CHANGE THIS!!! fastbit database location'''
    fb_DB = '/tmp/'               #ntop.getPreference ("fastbitDB");    #default location of the fastbit DB
    
    
    if fb_DB != None:
        databasePath=fb_DB
    pathFastBit=os.path.join(databasePath,'fastbit'+os.path.sep)
        
    
    form = cgi.FieldStorage();                      #get  from the url the parameter configfile that contains the 
                                                    #path+filename of the configfile to read
    '''Parameters for calling the autocomplete function'''
    selectAuto=form.getvalue('selectAuto')
    fromAuto=form.getvalue('fromAuto')
    
    documentRoot=os.getenv('DOCUMENT_ROOT', '.')
    
    if selectAuto:
        print>>sys.stderr, "PARAMETRO SELECT PASSATO "+str(selectAuto)
        #a request from the autocomplete script, return a json string with the matching files names
        ntop.sendHTTPHeader(1)
        ntop.sendString(expandSelect(selectAuto, pathFastBit, fromAuto))
        return
    elif fromAuto:
        ntop.sendHTTPHeader(1)
        ntop.sendString(expandFrom(fromAuto, pathFastBit))
        return
    else:
        
        history={'history':[]}         #object containing the last 10 queries successfully executed
        
        try:
            tempFile= open(os.path.join(ntopSpoolPath,tempQueryHistory), 'r')
            history=pickle.load(tempFile)
            
        except IOError:                                        #the tempFile does not exist or some other problem
            print>>sys.stderr, 'Fastbit query: IOError while accessing queries history '+tempQueryHistory
            history={'history':[]}                             #object containing the last 10 queries successfully executed
        except pickle.PickleError, pickle.UnpicklingError:
            print>>sys.stderr, "Error while loading the queries history removing file..."+os.path.join(ntopSpoolPath,tempQueryHistory)
            try:
                os.remove(os.path.join(ntopSpoolPath,tempQueryHistory))
            except:
                pass 
            raise
            
        selectArg=form.getvalue('select')
        fromArg=form.getvalue('from')
        whereArg=form.getvalue('where')
        limit = int(form.getvalue('limit', 100))
        
        carPosition=int(form.getvalue('carPosition', 0)) #to be used to expand in the middle of a string knowing the cursor position...
        
        
        queryPar=["", "", "", limit]        #show limit 100 as default
        
        ntop.printHTMLHeader('Fastbit Query', 1, 0)
        
        if selectArg and fromArg:
            queryPar=[selectArg, fromArg, whereArg, limit]
            try:
                #pipe = subprocess.Popen (['ntop.getPreference ("fastbit.fbquery")', "-c", selectArg, "-d", fromArg, "-q", whereArg, "-P", "-L", limit],
                print>>sys.stderr, "Query passed: SELECT %s FROM %s WHERE %s LIMIT %i" %(selectArg,os.path.join(pathFastBit, fromArg),  whereArg, limit)
                res = fastbit.query(os.path.join(pathFastBit, fromArg), selectArg, whereArg, limit)
                print>>sys.stderr, 'Number of records: %i' % len(res['values'])
            except:
                print>>sys.stderr, 'ERROR Executing query: '+("SELECT %s FROM %s WHERE %s LIMIT %i" %(selectArg,os.path.join(pathFastBit, fromArg),  whereArg, limit))
                res = {}
            if res != None and 'columns' in res:
                cols=res['columns']
                #control if the history list has reach the limit
                if len(history['history'])>=historyLimit:
                    history['history']=history['history'][0:historyLimit-1]
                #insert  the newly executed query at the beginning of the list 
                history['history']=["SELECT %s FROM %s WHERE %s" % (selectArg.upper(), fromArg.upper(), whereArg.upper())]+history['history']
                saveTempFile(history,os.path.join(ntopSpoolPath,tempQueryHistory))
            else:
                cols=[]
            if res !=None and 'values' in res:
                
                toFormat=getAddrCols(selectArg) #get a list of addr column numbers
                
                for x in res['values']:
                    for j in toFormat:
                        #for every number in the list format as an IP ADDR
                        try:
                            #just ipv4
                            x[j]=socket.inet_ntop(socket.AF_INET, struct.pack('>L',x[j]))
                        except:
                            #could be an ipv6
                            try:
                                x[j]=socket.inet_ntop(socket.AF_INET6, struct.pack('>L',x[j]))
                            except:
                                #failed ipv6 adn ipv4 conversion
                                print>>sys.stderr, "fastbit.py: IMPOSSIBLE TO FORMAT value: "+str(x[j])+" TO IP ADDR"
                        
                    #x[1]=socket.inet_ntop(socket.AF_INET,struct.pack('>L',x[1]))
                rows=res['values']
            #pprint.pprint(res, sys.stderr)
            
    try:
        basedir =  os.path.join(documentRoot,'python/templates')
        mylookup = TemplateLookup(directories=[basedir])
        myTemplate = mylookup.get_template(templateFilename)
        buf = StringIO()
        
        ctx = Context(buf, columns=cols, values=rows, queryPar=queryPar, queryHistory=history['history'])
        
        myTemplate.render_context(ctx)
        ntop.sendString(buf.getvalue())
    except:
        ntop.sendString(exceptions.html_error_template().render())
    
    ntop.printHTMLFooter()


'''HERE STARTS THE SCRIPTS'''

begin()