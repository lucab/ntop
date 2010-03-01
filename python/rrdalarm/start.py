'''
Created on 28/gen/2010

@author: Gianluca Medici
'''
import pickle, glob, threading

import ntop
import host
import os,os.path, sys, time, pprint

# Import modules for CGI handling
import cgi, cgitb
ntopSpoolPath=ntop.getSpoolPath()
nameFileConfig='/rrdAlarmConfig.txt'
tempFileName='rrdAlarmStart.tmp'
rrdFilesPath=ntop.getDBPath()+'/rrd'

documentRoot=os.getenv('DOCUMENT_ROOT', '.')

noFilesLine=[]                              #list of all the lines with no rrd file name found

# Imports for rrd
try:
    import rrdtool
except:
    ntop.printHTMLHeader('ntop Python Configuration Error',1,0)
    ntop.sendString("<b><center><font color=red>Please install <A HREF='http://sourceforge.net/projects/py-rrdtool/'>pyRRDTool</A></font><br># cd py_rrdTool_dir<br># sudo python setup.py install</center></b>")
    ntop.printHTMLFooter()
    sys.exit(0)

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
    sys.exit(0)

''' Class for object threshold that contains all the informations to check a list of rrdfiles and to trigger 
    the alarm action if the threshold is exceeded'''
class Threshold(object):
    '''
    classdocs
    '''
    __uniqueId = 0
    __listFilename = []
    __type=''
    __value = 0.0
    __numRepetition = 0
    __startTime = ''
    __endTime = ''
    __actionToPerform = ''
    __actionParameter= ''
    __timeBeforeNext = 0
    __actualRepetition=0
    __lastTimeTriggered=None
    
    def __init__(self, path, listRowConfig):
        '''
        Constructor
        '''
        if type(listRowConfig) != list :
            raise TypeError('listRowConfig')
        if len(listRowConfig) != 10:
            raise IndexError('listRowConfig')
        
        self.__uniqueId = int(listRowConfig[0])
        
        self.__type = listRowConfig[2]  
        self.__value = float(listRowConfig[3])
        self.__numRepetition = int(listRowConfig[4])
        self.__startTime = listRowConfig[5]
        self.__endTime = listRowConfig[6]
        self.__actionToPerform = listRowConfig[7]
        self.__actionParameter= listRowConfig[8]
        self.__timeBeforeNext =float(listRowConfig[9])
        
        listFile = glob.glob((path + '/' + listRowConfig[1]))   #expand the * and ? into a list of files  
        if len(listFile) > 0 :
            self.__listFilename = listFile
            print>>sys.stderr, 'Found %i Files for ID: %i' % (len(listFile), self.__uniqueId)
        else:
            raise IOError('No File Found %s for ID: %i' ((path + '/' + listRowConfig[1])), self.__uniqueId)
    
    
    def getUniqueId(self):
        return self.__uniqueId
    
    def getListFilename(self):
        return self.__listFilename
    
    def getType(self):
        return self.__type
    
    def getValue(self):
        return self.__value
    
    def getNumRepetition(self):
        return self.__numRepetition
    
    def getStartTime(self):
        return self.__startTime
    
    def getEndTime(self):
        return self.__endTime
    
    def getActionToPerform(self):
        return self.__actionToPerform
    
    def getActionParameter(self):
        return self.__actionParameter
    
    def getTimeBeforeNext(self):
        return self.__timeBeforeNext
    
    def increseRepetition(self):
        self.__actualRepetition= self.__actualRepetition + 1
    
    def clearRepetition(self):
        self.__actualRepetition= 0
    
    '''Returns true if the threshold exceed value passed '''
    def checkIfFire(self, value):
        if not self.__type:
            return False
        if value== None:
            return False
        
        #check if value exceed above the threshold    or below the threshold
        if (self.__type == 'above' and value>self.__value) or (self.__type == 'below' and value<self.__value):
            #print>>sys.stderr, 'Inside above'
            timeActual = time.clock()
            self.increseRepetition()
            
            #the value exceed check if it needs more repetition to fire or is too early to fire again
            if self.__actualRepetition >= self.__numRepetition and ( not self.__lastTimeTriggered or self.__timeBeforeNext==0 or ((timeActual-self.__lastTimeTriggered) > self.__timeBeforeNext)):
                
                self.__lastTimeTriggered=timeActual
                self.clearRepetition()
                return True
            else:
                return False
        
        else:       #restart repetition count if a value does not exceed the threshold
            self.clearRepetition()

''' Check the existence of the rrd database files that maintain history of this script'''
def updateDBS(rrdFilesPath,time, resultsValue, durationValue):
    rrdAlarmDbPath=rrdFilesPath+'/rrdalarm/'
    if not os.path.exists(rrdAlarmDbPath) or not os.path.isdir(rrdAlarmDbPath):
        os.mkdir(rrdAlarmDbPath)
    
    nameDuration="duration.rrd"
    nameResults="results.rrd"
    archives=['RRA:AVERAGE:0.5:1:60', 
              'RRA:AVERAGE:0.5:30:6']#1 hour and 3 hours data
    try:
        rrdtool.update(rrdAlarmDbPath+nameDuration, 'N:'+str(durationValue))
#        print>>sys.stderr, 'Updating'+str(durationValue)
    except:
        
        dataSources=['DS:duration:GAUGE:120:0:U']
        
        rrdtool.create(rrdAlarmDbPath+nameDuration, '--start', str(time), '--step', str(60), dataSources[0], archives[0], archives[1] )
        rrdtool.update(rrdAlarmDbPath+nameDuration,'N:'+str(durationValue))
    
    try:
        rrdtool.update(rrdAlarmDbPath+nameResults, 'N:'+str(resultsValue))
        
    except:
        
        dataSources=['DS:results:GAUGE:120:0:U']
        
        rrdtool.create(rrdAlarmDbPath+nameResults, '--start', str(time), '--step', str(60), dataSources[0], archives[0], archives[1] )
        rrdtool.update(rrdAlarmDbPath+nameResults, 'N:'+str(resultsValue))


''' Reads all the lines of filename and return a list 
    of threshold object if all goes well'''
def readConfigFile(rrdFilesPath,fileName):
    print>>sys.stderr, ('Reading configuration for '+fileName)
    retList=[]
    try:
        cFile=open(fileName, 'r')
        for line in cFile:
            line=line.rstrip()
            if line[0] != '#':
                try:
                    retList.append(Threshold(rrdFilesPath, line.split('\t')))
                except IOError as e:
                    print>>sys.stderr, str(e)
                    noFilesLine.append(line)
        cFile.close()
        return retList
    except:
        print>>sys.stderr, 'Some problem reading configurationFile'
        raise
        return retList
    
''' Create a new empty configuration dictionary for the nameFileConf'''
def createNewConfiguration(rrdFilesPath, nameFileConf, timeStart):
    return {'lastModified': os.path.getmtime(nameFileConf), 'timeStart' :timeStart,  'listThresholds':readConfigFile(rrdFilesPath,nameFileConf)}#, 'lastAlarmsFired':[]}

''' Function that create or replace a tempFile containing the the persistance 
    information for resuming this script status at next run '''
def saveTempFile(configuration):
    #the changes was made to the configuration, will be saved in tempfile
    global tempFileName
    try:
        tempFile= open(ntopSpoolPath+'/'+tempFileName, 'w')
        pickle.dump(configuration, tempFile, pickle.HIGHEST_PROTOCOL)
        tempFile.close()
    except:
        print>>sys.stderr, 'Error saving the temp configuration on disk!'
        return -1
    return 0

    
def performActions(parameterDict):
    
    global documentRoot

    if len(parameterDict) >0:
        try:
            for key in parameterDict.keys():
                scriptName=str(parameterDict[key]['actionToPerform'])+'.py'
                command='python %s/python/rrdalarm/scripts/%s -p "%s" -t "%s"' % (documentRoot,scriptName,str(key),str(parameterDict[key]['textAlarm']))
                #print>>sys.stderr, command
                os.system(command)
        except:
            raise
            #print>>sys.stderr, 'Python probably bug 1731717, the alarm was performed anyway'
            
    print>>sys.stderr, '%i actions were performed' % len(parameterDict)


def begin():
        global nameFileConfig, ntopSpoolPath, tempFileName
        configuration= None
        timeStart=time.time()
        
        alarmsFired=0
        checkedFiles=0
        fmt='%a, %d %b %Y %H:%M:%S'                     #format of the time showed
        form = cgi.FieldStorage();                              #get the parameter passed via the url 
        noHTML=bool(form.getvalue('noHTML'))
        configFile=form.getvalue('configFile')
        if configFile and len(configFile)>0:
            nameFileConfig='/'+str(configFile)
        try:
            tempFile= open(ntopSpoolPath+'/'+tempFileName, 'r')
            
            configuration=pickle.load(tempFile)
            tempFile.close()
            if configuration and (timeStart < float(configuration['timeStart'])+float(60)):
                ntop.sendHTTPHeader(1)
                ntop.printHTMLHeader('RRD Alarm Called too early!',1,0)
                ntop.sendString("Wait at least a minute. Last Time started: %s" % time.strftime(fmt,time.localtime(configuration['timeStart'])))
                ntop.printHTMLFooter()
                #print>>sys.stderr, 'Before lock'
                
                #print>>sys.stderr, 'Returning 0 after lock'
                return 0;                                 #exit because the script was started less than one minute ago
                
            else:
                configuration['timeStart']=timeStart
    
        except IOError:                                 #the tempFile does not exist or some other problem
            print>>sys.stderr, 'IOError while accessing tempfile '+tempFileName
            configuration=createNewConfiguration(rrdFilesPath, ntopSpoolPath+nameFileConfig, timeStart)
        
        except pickle.PickleError, pickle.UnpicklingError: 
            print>>sys.stderr,  "Problems during the UnPickling load, tempFile Delete..."
            os.remove(ntopSpoolPath+'/'+tempFileName)
            return -1
        #finally: condition.notify()
        
        if configuration['lastModified'] != os.path.getmtime(ntopSpoolPath+nameFileConfig):
            #if the configuration file has been changed the temp file has to be rebuild and so the configuration dictionary 
            configuration=createNewConfiguration(rrdFilesPath, ntopSpoolPath+nameFileConfig, timeStart)
            
        listRows=[]
        parameterDic={}                                         #for each parameter inserted as a key a tupla will be assigned 'parameter':{actionToPerform, text}
        
        
        for threshold in configuration['listThresholds']:       #for all the thresholds
            listFiles=threshold.getListFilename()
            checkedFiles=checkedFiles+len(listFiles)
            
            for fileN in listFiles:                             #for all the filenames referred by the threshold        
                #rrd_argv=[fileN,'AVERAGE', '--start', threshold.getStartTime(), '--end', threshold.getStartTime()]
                #Return :((start, end, step), (name1, name2, ...), [(data1, data2, ..), ...])
                
                #print>>sys.stderr, '\nGUARDA QUI'+threshold.getStartTime()+' '+str(type(threshold.getEndTime()))
                rrdObj=rrdtool.fetch(fileN, 'AVERAGE', '--start', threshold.getStartTime(), '--end', threshold.getEndTime())
                
                #print>>sys.stderr, '\nRRDFETCH RETURNED:'
                #pprint.pprint(rrdObj, sys.stderr) #print object for debug purpose only
                step=rrdObj[0][2]
                start=rrdObj[0][0]
                end=float(rrdObj[0][1])
                
                valueDataTuple=rrdObj[2]                        #check this out, not sure witch data object is
                #for all the values returned check the threshold if alarm has to be fired
                i=0
                for value in valueDataTuple:
                    i=i+1
                    
                    timeA= (step*i)+start
                    if threshold.checkIfFire(value[0]):         #controls if the threshold was exceeded  
                        notFired=False
                        alarmsFired=alarmsFired+1
                        listRows.append((threshold.getUniqueId(), fileN, value[0], threshold.getType(), threshold.getValue(), time.strftime(fmt,time.localtime(timeA)), timeA,threshold.getActionToPerform(), 'ALARM FIRED'))
                        strAlarm='<ALARM>\nID: %i FILENAME: %s\nVALUE: %s TYPE: %s THRESHOLD VALUE: %f\n LOCALTIME: %s START: %s END: %s\n</ALARM>\n' % (threshold.getUniqueId(), fileN, value[0], threshold.getType(), threshold.getValue(), time.strftime(fmt,time.localtime(timeA)), threshold.getStartTime(), threshold.getEndTime())
                        if parameterDic.has_key(threshold.getActionParameter()):
                            parameterDic[threshold.getActionParameter()]['textAlarm']=parameterDic[threshold.getActionParameter()]['textAlarm']+strAlarm
                        else:
                            parameterDic[threshold.getActionParameter()]={'actionToPerform':threshold.getActionToPerform(), 'textAlarm':strAlarm}
                        break
                        #print>>sys.stderr, 'The type of the threshold was misconfigured!'
                else: #no alarm was fired
                    listRows.append((threshold.getUniqueId(), fileN, '-', threshold.getType(), threshold.getValue(), time.strftime(fmt,time.localtime(end)), end, 'None', 'OK'))                                           #at least one alarm was fired, adding the action to perform, text and parameter to the global dictionary
                    
        
        saveTempFile(configuration)                             #save all the informations usefull for future calling of this script 
        
        performActions(parameterDic)                 #performs all the actions for the alarms fired (if any)
        
        duration=float(time.time()-timeStart)
        updateDBS(rrdFilesPath,int(timeStart), alarmsFired, duration)        #update rrds that trace the history of this script  TODO check where to place this
       
        ntop.sendHTTPHeader(1)
        
        
        if not noHTML:                                          #if this parameter was passed and if true send just the empty http response        
            ntop.printHTMLHeader('RRD Alarm Report',1,0)
            try:
                documentRoot=os.getenv('DOCUMENT_ROOT', '.')
                basedir =  documentRoot+'/python/templates'
                mylookup = TemplateLookup(directories=[basedir])
                myTemplate = mylookup.get_template('rrdAlarmStart.tmpl')
                buf = StringIO()
                ctx = Context(buf,listRows=listRows, duration=duration, checkedFiles=checkedFiles, alarmsFired=alarmsFired)
                myTemplate.render_context(ctx)
                ntop.sendString(buf.getvalue())
            except:
                ntop.sendString(exceptions.html_error_template().render())
                
                return 1
            #finally:
                #condition.notify()
            ntop.printHTMLFooter()
       
        print>>sys.stderr, '%s CET Exit rrdAlarm' % time.strftime(fmt,time.localtime(time.time()))
        return 0

def mainT():
    #the main thread will wait seconds before terminating and killing the control thread, if the control finish before all is good and terminates successfully    
    control=threading.Thread(target=begin)    #create the actual thread that performs the controls
    seconds=50
    control.start()
    #wait max second for the termination of the control thread
    control.join(seconds)
    
    if control.isAlive():
        print>>sys.stderr, 'The thread was still alive'
        raise RuntimeError('The RRDAlarm script lasted more that %d seconds!' % seconds)
    else:
        print>>sys.stderr, 'Correct termination'
    


'''
THE SCRIPT STARTS HERE
'''    

from StringIO import StringIO

if os.getenv('REQUEST_METHOD', 'GET') == 'GET':             # The script can be called only by get method
    
    try:
        mainT()        
    except RuntimeError as x:
        ntop.sendHTTPHeader(1)
        ntop.printHTMLHeader(str(x)+' Aborted.',1,0)
        ntop.printHTMLFooter()
else:       #script called by some other method rather that GET, return not implemented
    ntop.returnHTTPnotImplemented()