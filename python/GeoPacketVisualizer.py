
'''
Created on 20 Dec 2009

@author: Gianluca Medici

This module is made to show a page inside ntop summarizing the geoLocation of all
host seen and visualize them on a world map. The map is interactive and shows in addiction
the information regarding each nation's packets count (represented with different tonality of colours).
Clicking on a region of a map or on a row of the country's table is possible to zoom to
that particular nation and see the approximate position of the cities in witch the hosts are located.
'''
import decimal
import ntop
import host
import os.path
import sys
#import pprint
# Import modules for CGI handling
import cgi, cgitb

from StringIO import StringIO

exceptions_so_far=0

try:
    import json

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
        exceptions_so_far=1
except:
    ntop.printHTMLHeader('ntop Python Configuration Error', 1, 1)
    ntop.sendString("<b><center><font color=red>Please install JSON support in python</font><p></b><br>E.g. 'sudo apt-get install python-json' (on Debian-like systems)</font></center>")
    ntop.printHTMLFooter()    
    exceptions_so_far=1

# Fix encoding
reload(sys)
sys.setdefaultencoding("latin1")

class Town(object):
    '''
    classdocs
    '''
    __name=''
    __latitudine=0
    __longitudine=0
    __totalHosts=0

    def __init__(self, name, latitudine, longitudine, numHosts ):
        '''
        Constructor
        '''
        self.__name=name.decode('latin1')
        self.__latitudine=latitudine
        self.__longitudine=longitudine
        self.__totalHosts=numHosts

    def getName(self):
        return self.__name

    def getLatitude(self):
        return self.__latitudine

    def getLongitude(self):
        return self.__longitudine

    def getTotalHosts(self):
        return self.__totalHosts

    def addTotal(self, numHosts):
        self.__totalHosts+=numHosts

    def getRow(self):
        return {'c':[{'v':float(self.__latitudine)}, {'v':float(self.__longitudine)} , {'v':self.__totalHosts} , {'v':self.__name}]}

class Country(object):
    '''
    classdocs
    '''
    __code = ''
    __name = ''
    __total = 0
    __dictionaryTown = {}

    def __init__(self, code, name, numHosts):
        '''
        Constructor
        '''
        self.__code = code
        
        self.__name = name.decode('latin1')
        self.__total = numHosts
        self.__dictionaryTown = {}

    def addCity(self, city, latitude, longitude, numHosts):
        if self.__dictionaryTown.has_key(city):
            self.__dictionaryTown[city].addTotal(numHosts)
        else:
            self.__dictionaryTown[city]= Town(city, latitude, longitude, numHosts)

    def getCode(self):
        return self.__code 

    def getName(self):
        return self.__name

    def getTotal(self):
        return self.__total

    def addTotal(self, total):
        self.__total+=total

    def getDictionaryCities(self):
        return self.__dictionaryTown

    def getRow(self):
        
        return {'c':[{'v':self.__code}, {'v':self.__total} , {'v':self.__name} ]}

    def dictToList(self):
        rows=[]
        unk=-1
        i=0
        for x in self.__dictionaryTown :
            if self.__dictionaryTown[x].getName() == 'Unknown' and unk == -1:
                unk=i
            rows.append(self.__dictionaryTown[x].getRow());
            i=i+1
        return {'lista':rows, 'unknown':unk}
    
'''
Return a string of formatted json data for building the countries table and the cities table
'''
def getJsonData(dictionaryCountries, totalHosts,unknownCountries, unknownCities):
    dataJ={'rowsTCountries': None, 'tablesCities': []}
    mainRows=[]
    for x in dictionaryCountries:
        mainRows.append(dictionaryCountries[x].getRow())
        dataJ['tablesCities'].append({'code':dictionaryCountries[x].getCode(), 'citiesRows': dictionaryCountries[x].dictToList()})
    
    dataJ['rowsTCountries']= mainRows
    dataJ['totalHosts']= totalHosts
    dataJ['unknownCountries']= unknownCountries
    dataJ['unknownCities']= unknownCities
    #pprint.pprint(dataJ, sys.stderr)
    try:
        return json.dumps(dataJ, True)
    except:
        return 'false'

if exceptions_so_far == 0:
    dictionaryCountries = {}
    
    totalHosts = 0
    unknownCountries = 0
    unknownCities = 0
    flag = 's'                                  # s (default) for sent packets r for received, b for both
    SIXDECIMAL = decimal.Decimal(10) ** -6      # decimals are all fixed to 6 es. 0.000000
    
    # Parse URL
    cgitb.enable();
    
    form = cgi.FieldStorage();
    
    if form.getvalue('OP') == 'Change':
        flag = form.getvalue('countHosts', 's')
    
    while ntop.getNextHost(0):
        totalHosts += 1
        geo = host.geoIP()
        
        countryCode = geo.get('country_code', '')
        countryName = geo.get('country_name', '')
        city = geo.get('city', '')
        
        lat = str(geo.get('latitude', '0.000000'))
        lon = str(geo.get('longitude', '0.000000'))
        
        latitude = decimal.Decimal(lat).quantize(SIXDECIMAL)
        longitude = decimal.Decimal(lon).quantize(SIXDECIMAL)
        
        if not countryCode or countryCode == 'EU' or countryCode == 'AP' :      # the country was not found therefore the city was not found, everything in the object is set accordingly
            countryCode = ''
            city = ''
            unknownCountries += 1
        elif not city :   
            unknownCities += 1                                     # the country was found but not the city, to list this case the city name is set to Unknown
            city = 'Unknown'
            latitude = decimal.Decimal('0.000000')
            longitude = decimal.Decimal('0.000000')

        if countryCode :
            if dictionaryCountries.has_key(countryCode):           # the dictionary of nations already has the nationCode listed 
                country = dictionaryCountries[countryCode]
                country.addTotal(1)
            else:
                country = Country(countryCode, countryName, 1)
                dictionaryCountries[countryCode] = country

        if city: 
            country.addCity(city, latitude, longitude, 1)          # insert the city found in the citiesDictionary of this nation object
    
    if os.getenv('REQUEST_METHOD', 'GET') == 'POST':    
        ntop.sendHTTPHeader(12)
        ntop.sendString(getJsonData(dictionaryCountries, totalHosts, unknownCountries, unknownCities))
    else:
        ntop.printHTMLHeader('Host Map: Region View', 1, 0)
        
        if totalHosts == 0:
            ntop.printFlagedWarning('No hosts have been detected by ntop yet')
        elif len(dictionaryCountries) == 0:
            ntop.printFlagedWarning('No hosts have been successfully geo-located by ntop yet')
        else:
            try:
                basedir =  os.getenv('DOCUMENT_ROOT', '.')+'/python/templates'
                mylookup = TemplateLookup(directories=[basedir],output_encoding='utf-8', input_encoding='latin1',encoding_errors='replace', default_filters=['decode.utf8'])
                myTemplate = mylookup.get_template('GeoPacketVisualizer.tmpl')
                buf = StringIO()
                ctx = Context(buf, countries = dictionaryCountries, totalHosts = totalHosts, unknownCountries = unknownCountries, 
                              unknownCities = unknownCities, filename = os.path.basename(__file__))
                myTemplate.render_context(ctx)
                ntop.sendString(buf.getvalue())
            except:
                ntop.sendString(exceptions.html_error_template().render())
        
        ntop.printHTMLFooter()
