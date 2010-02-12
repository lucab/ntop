'''
Created on 28/gen/2010

@author: Gianluca Medici
'''
import pickle, glob, threading

import ntop
import host
import os.path, sys, time, pprint

# Import modules for CGI handling
import cgi, cgitb

nameFileConfig=ntop.getSpoolPath()+'/rrdAlarmConfig.txt'
tempFileName='rrdAlarmStart.tmp'
rrdFilesPath=ntop.getDBPath()+'/rrd'
rrdDuration=None
rrdResults=None

noFilesLine=[]

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
    __timeBeforeNext = 0
    __actualRepetition=0
    __lastTimeTriggered=None
    
    def __init__(self, path, listRowConfig):
        '''
        Constructor
        '''
        if type(listRowConfig) != list :
            raise TypeError('listRowConfig')
        if len(listRowConfig) != 9:
            raise IndexError('listRowConfig')
        
        self.__uniqueId = int(listRowConfig[0])
        
        self.__type = listRowConfig[2]  
        self.__value = float(listRowConfig[3])
        self.__numRepetition = int(listRowConfig[4])
        self.__startTime = listRowConfig[5]
        self.__endTime = listRowConfig[6]
        self.__actionToPerform = listRowConfig[7]
        self.__timeBeforeNext =float(listRowConfig[8])
        
        listFile = glob.glob((path + '/' + listRowConfig[1]))   #expand the * and ? into a list of files  
        if len(listFile) > 0 :
            self.__listFilename = listFile
            print>>sys.stderr, 'Found '+ str(len(listFile))+ ' Files'
        else:
            #print>>sys.stderr, 'No File Found'+path + '/' + listRowConfig[1]
            raise IOError('No File Found'+(path + '/' + listRowConfig[1]))
    
    #not really used for now
    def printThis(self, separator):
        tmp = ''
        for x in self._filename:
            tmp = tmp + x + separator
        
        return (str(self.__uniqueId) + separator + '[' + tmp + ']' + separator + self.__type + separator +
        str(self.__value) + separator + str(self.__numRepetition) + separator + 
        str(self.__startTime) + separator + str(self.__endTime) + +separator + 
        str(self.__actionToPerform) + separator + str(self.__timeBeforeNext) + '\t')


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
        #print>>sys.stderr, 'Valori '+str(value)+' '+self.__type+' '+str(self.__value)+' '+str(value>self.__value)
        if self.__type == 'above' and value>self.__value:
            #print>>sys.stderr, 'Inside above'
            timeActual = time.clock()
            self.increseRepetition()
            
            #print>>sys.stderr, 'Boolean '+str(timeActual-self.__lastTimeTriggered)+' '+str((timeActual-self.__lastTimeTriggered) > self.__timeBeforeNext)
            #print>>sys.stderr, 'Boolean 2 '+str(timeActual)+' '+ str(self.__lastTimeTriggered)+" diff "+str(timeActual-self.__lastTimeTriggered)
            #print>>sys.stderr, 'Type '+ str(type(timeActual))+' '+str(type(self.__lastTimeTriggered))+str(type((timeActual-self.__lastTimeTriggered)))
            if self.__actualRepetition >= self.__numRepetition and ( not self.__lastTimeTriggered or self.__timeBeforeNext==0 or ((timeActual-self.__lastTimeTriggered) > self.__timeBeforeNext)):
                
                self.__lastTimeTriggered=timeActual
                self.clearRepetition()
                return True
            else:
                return False
        elif self.__type == 'below' and value<self.__value:
            #print>>sys.stderr, 'Inside below'
            timeActual = time.clock()
            self.increseRepetition()
            
            if self.__actualRepetition >= self.__numRepetition and ( not self.__lastTimeTriggered or self.__timeBeforeNext==0 or ((timeActual-self.__lastTimeTriggered) > self.__timeBeforeNext)):
                
                self.__lastTimeTriggered=timeActual
                self.clearRepetition()
                return True
            else:
                return False
        else:       #restart repetition count if a value does exceed the threshold
            self.clearRepetition()


''' Check the existence of the rrd database files that maintain history of this script'''
def updateDBS(time, resultsValue, durationValue):
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
#        print>>sys.stderr, 'Updating2'+str(resultsValue)
    except:
        
        dataSources=['DS:results:GAUGE:120:0:U']
        
        rrdtool.create(rrdAlarmDbPath+nameResults, '--start', str(time), '--step', str(60), dataSources[0], archives[0], archives[1] )
        rrdtool.update(rrdAlarmDbPath+nameResults, 'N:'+str(resultsValue))


''' Reads all the lines of filename and return a list 
    of threshold object if all goes well'''
def readConfigFile(fileName):
    print>>sys.stderr, ('Reading configuration for '+fileName)
    retList=[]
    try:
        cFile=open(fileName, 'r')
        for line in cFile:
            line=line.rstrip()
            if line[0] != '#':
            #line=line[1 ,-1]
                try:
                    retList.append(Threshold(rrdFilesPath, line.split('\t')))
                except IOError as e:
                    print>>sys.stderr, str(e)
                    noFilesLine.append(line)
        cFile.close()
        return retList
    except:
        print>>sys.stderr, 'Some problem reading configfile'
        raise
        return retList
    
''' Create a new empty configuration dictionary for the nameFileConf'''
def createNewConfiguration(nameFileConf, timeStart):
    return {'lastModified': os.path.getmtime(nameFileConf), 'timeStart' :timeStart,  'listThresholds':readConfigFile(nameFileConf)}#, 'lastAlarmsFired':[]}
    


''' Function that create or replace a tempFile containing the the persistance 
    information for resuming this script status at next run '''
def saveTempFile(configuration):
    #the changes was made to the configuration, will be saved in tempfile
    try:
        tempFile= open(ntop.getSpoolPath()+'/'+tempFileName, 'w')
        pickle.dump(configuration, tempFile, pickle.HIGHEST_PROTOCOL)
        tempFile.close()
    except:
        print>>sys.stderr, 'Error saving the temp configuration on disk!'
        return -1
    return 0

def begin():
    configuration= None
    timeStart=time.time()
    
    alarmsFired=0
    checkedFiles=0
    

    try:
        tempFile= open(ntop.getSpoolPath()+'/'+tempFileName, 'r')
        print>>sys.stderr,ntop.getSpoolPath()+'/'+tempFileName
        configuration=pickle.load(tempFile)
        tempFile.close()
        if configuration and (timeStart < float(configuration['timeStart'])+float(60)):
            ntop.sendHTTPHeader(1)
            ntop.printHTMLHeader('RRD Alarm Called too soon!',1,0)
            ntop.sendString("Wait at least a minute.")
            ntop.printHTMLFooter()
            return;#exit because the script was started less than one minute ago
        else:
            configuration['timeStart']=timeStart

    except IOError:         #the tempFile does not exist or some other problem
        print>>sys.stderr, 'IOError while accessing tempfile '+tempFileName
        configuration=createNewConfiguration(nameFileConfig, timeStart)
    
    except pickle.PickleError, pickle.UnpicklingError: 
        print>>sys.stderr,  "Problems during the UnPickling load, tempFile Delete..."
        os.remove(ntop.getSpoolPath()+'/'+tempFileName)
        return -1
    
    #print>>sys.stderr, str(os.path.getmtime(nameFileConfig))
    if configuration['lastModified'] != os.path.getmtime(nameFileConfig):
        #if the configuration file has been changed the temp file has to be rebuild and so the configuration dictionary 
        configuration=createNewConfiguration(nameFileConfig, timeStart)
        
    listRows=[]
    #pprint.pprint(configuration, sys.stderr)
    for threshold in configuration['listThresholds']:
        listFiles=threshold.getListFilename()
        checkedFiles=checkedFiles+len(listFiles)
        #print>>sys.stderr, 'Inside '+ str(len(listFiles))
        for fileN in listFiles:
            #rrd_argv=[fileN,'AVERAGE', '--start', threshold.getStartTime(), '--end', threshold.getStartTime()]
            #Return :((start, end, step), (name1, name2, ...), [(data1, data2, ..), ...])
            
            #print>>sys.stderr, '\nGUARDA QUI'+threshold.getStartTime()+' '+str(type(threshold.getEndTime()))
            rrdObj=rrdtool.fetch(fileN, 'AVERAGE', '--start', threshold.getStartTime(), '--end', threshold.getEndTime())
            
            #print>>sys.stderr, '\nRRDFETCH RETURNED:'
            #pprint.pprint(rrdObj, sys.stderr) #print object for debug purpose only
            step=rrdObj[0][2]
            start=rrdObj[0][0]
            end=float(rrdObj[0][1])
            
            valueDataTuple=rrdObj[2]     #check this out, not sure witch data object is
            #for all the values returned check the threshold if alarm has to be fired
            i=0
            notFired=True
            for value in valueDataTuple:
                i=i+1
               
                timeA= (step*i)+start
                if threshold.checkIfFire(value[0]):
                    notFired=False
                    alarmsFired=alarmsFired+1
                    listRows.append((threshold.getUniqueId(), fileN, value[0], threshold.getType(), threshold.getValue(), time.asctime(time.localtime(timeA)), timeA,threshold.getActionToPerform(), 'ALARM FIRED'))
                    print>>sys.stderr, threshold.getActionToPerform() #thisAction has to be run
                    #print>>sys.stderr, 'The type of the threshold was misconfigured!'
            if notFired:
                listRows.append((threshold.getUniqueId(), fileN, '-', threshold.getType(), threshold.getValue(), time.asctime(time.localtime(end)), end, threshold.getActionToPerform(), 'OK'))
    saveTempFile(configuration) 
                
    duration=float(time.time()-timeStart)
    updateDBS(int(timeStart), alarmsFired, duration)
    ntop.sendHTTPHeader(1)
    
    form = cgi.FieldStorage();                  #get the parameter passed via the url 
    noHTML=bool(form.getvalue('noHTML'))
    
    if not noHTML:                              #if this parameter was passed and is true send the response http empty        
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
        
        ntop.printHTMLFooter()
   
    print>>sys.stderr, 'Exit rrdAlarm'
    
    #rrdObj2=rrdtool.fetch(rrdFilesPath+'/rrdAlarm/results.rrd', 'AVERAGE', '--start', 'now-1h', '--end', 'now')
    #pprint.pprint(rrdObj2, sys.stderr) #print object for debug purpose only
    return 0
#procRRDAlarm=subprocess.Popen()
#wait_timeout(procRRDAlarm, 60)

def mainT():
    # Imports for rrd
    try:
        import rrdtool
    except:
        ntop.printHTMLHeader('ntop Python Configuration Error',1,0)
        ntop.sendString("<b><center><font color=red>Please install <A HREF=http://sourceforge.net/projects/py-rrdtool/>pyRRDTool/A></font> cd py_rrdTool_dir (sudo python setup.py install)</center></b>")
        ntop.printHTMLFooter()
        return
    
    from StringIO import StringIO
    
    
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
    
    def wait_timeout(thread, seconds):
        '''Wait for thread to finish, or terminate (and subsequently kill it) after timeout'''
        start=time.time()
        end=start+seconds
        interval= min(seconds / 1000.0, .25)            #interval to that the main thread sleep before checking if control is finished
    
        while True:
            result= thread.isAlive()
            if not result: 
                return 0                      # control thread finished
            if time.time() >= end:
                raise RuntimeError('The RRDAlarm script lasted more that %d seconds!' % seconds)
            
            time.sleep(interval)
    
    control=threading.Thread(target=begin)    #create the actual thread that performs the controls
    control.start()                           
    
    wait_timeout(control, 50)                 #the main thread will wait seconds before terminating and killing the control thread, if the control finish before all is good and terminates successfully

'''
THE SCRIPT STARTS HERE
'''    
if os.getenv('REQUEST_METHOD', 'GET') == 'GET':             # The script can be called only by get method 
    try:
        mainT()
    except RuntimeError as x:
        ntop.sendHTTPHeader(1)
        ntop.printHTMLHeader(str(x)+' Aborted.',1,0)
        ntop.printHTMLFooter()
    #print>>sys.stderr, 'Fine start'
else:       #requested by a some other method rather that GET return not implemented
    ntop.returnHTTPnotImplemented()