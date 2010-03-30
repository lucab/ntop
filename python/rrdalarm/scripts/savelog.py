'''
Created on 19/feb/2010

@author: Gianluca Medici
'''
import sys, time, os.path
#this parameter defines the directory in witch the log files will be placed
pathFile='tmp/'                #Remember to set this parameter to your liking

def begin():
    global pathFile
    if len(sys.argv)!=5 or sys.argv[1]!= '-p' or not sys.argv[2] or sys.argv[3]!= '-t' or not sys.argv[4]:
        print 'USAGE %s -p <parameter> -t <text>' % sys.argv[0]
    else:
        filename=sys.argv[2]
        text = sys.argv[4]
        
        gmt=time.localtime(time.time())
        fmt='%a, %d %b %Y %H:%M:%S'
        st=time.strftime(fmt, gmt)
        
        try:
            logFile= open(os.path.join(pathFile,filename), 'a')
            logFile.write("Last Update time: %s\n" % st)
            
            logFile.write(text)
            logFile.close()
        except IOError:
            print>>sys.stderr,  "IOEXCEPTION writing file "+os.path.join(pathFile,filename)
            return 1
        return 0
    
'''Scripts starts here'''
begin()