'''
Created on 20 Dec 2009

@author: Gianluca Medici

This module is made to show a page inside ntop summarizing the geoLocation of all
host seen and visualize them on a world map. The map is interactive and shows in addiction
the information regarding each nation's packet count (represented with different tonality of colours).
Clicking on a region of a map or on a row of the country's table is possible to zoom to
that particular nation and see the approximate position of the cities in witch the hosts are located.
'''
import decimal
import ntop
import host
import os.path
import sys
import pprint

# Import modules for CGI handling
import cgi, cgitb

from StringIO import StringIO

# Imports for mako
try:
    from mako.template import Template
    from mako.runtime import Context
    from mako.lookup import TemplateLookup
    from mako import exceptions
except:
    ntop.printHTMLHeader('ntop Python Configuration Error')
    ntop.sendString("<b><center><font color=red>Please install <A HREF=http://www.makotemplates.org/>Mako</A> template engine</font> (sudo easy_install Mako)</center></b>")
    ntop.printHTMLFooter()    
    os.exit(0)

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
        self.__name=name
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
        self.__name = name
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

ntop.printHTMLHeader('Host Map: Region View')

if totalHosts == 0:
    ntop.printFlagedWarning('No hosts have been detected by ntop yet')
else:
    try:
        basedir =  os.getenv('DOCUMENT_ROOT', '.')+'/python/templates'
        mylookup = TemplateLookup(directories=[basedir])
        myTemplate = mylookup.get_template('GeoPacketVisualizer.tmpl')
        buf = StringIO()
        ctx = Context(buf, countries = dictionaryCountries, totalHosts = totalHosts, unknownCountries = unknownCountries, 
                      unknownCities = unknownCities, filename = os.path.basename(__file__))
        myTemplate.render_context(ctx)
        ntop.sendString(buf.getvalue())
    except:
        ntop.sendString(exceptions.html_error_template().render())

ntop.printHTMLFooter()
