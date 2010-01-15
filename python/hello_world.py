import ntop;
import host;
import pprint

# Import modules for CGI handling
import cgi, cgitb

# Parse URL
cgitb.enable();

form = cgi.FieldStorage();

fingerprint = form.getvalue('fingerprint', default="fbquery")

ntop.printHTMLHeader("Welcome to ntop+Python ["+ntop.getPreference("ntop.devices")+"]", 1, 1);


countries = {};

while ntop.getNextHost(0):
    geo = host.geoIP()
    country = geo.get('country_name', '')

    if country != "":
        if(countries.get(country, '') == ''):
            countries[country] = 1
        else:
            countries[country] = countries.get(country, '')+1

if(len(countries) > 0):
    ntop.sendString(" <script type=\'text/javascript\' src=\'http://www.google.com/jsapi\'></script>\n")
    ntop.sendString("  <script type=\'text/javascript\'>\n")
    ntop.sendString("   google.load(\'visualization\', \'1\', {\'packages\': [\'geomap\']});\n")
    ntop.sendString("   google.setOnLoadCallback(drawMap);\n")
    
    ntop.sendString("    function drawMap() {\n")
    ntop.sendString("      var data = new google.visualization.DataTable();\n")
    ntop.sendString("      data.addRows("+str(len(countries))+");\n")
    ntop.sendString("      data.addColumn(\'string\', \'Country\');\n")
    ntop.sendString("      data.addColumn(\'number\', \'Host(s)\');\n")
    
    i = 0;
    for key in countries:
        ntop.sendString(" data.setValue("+str(i)+", 0, \'"+key+"\');\n")
        ntop.sendString(" data.setValue("+str(i)+", 1, "+str(countries[key])+");\n")
        i = i+1

    ntop.sendString("      var options = {};\n")
    ntop.sendString("      options[\'dataMode\'] = \'regions\';\n")
    ntop.sendString("      var container = document.getElementById(\'map_canvas\');\n")
    ntop.sendString("      var geomap = new google.visualization.GeoMap(container);\n")
    ntop.sendString("      geomap.draw(data, options);\n")
    ntop.sendString("  };\n")
    ntop.sendString("  </script>\n")
    ntop.sendString("<center><div id=\'map_canvas\'></div></center><p>\n")

ntop.sendString("<center><table border>\n");
ntop.sendString("<tr><th>MAC Address</th><th>IP Address</th><th>Name</th><th># Sessions</th><th># Contacted Peers</th><th>Fingerprint</th><th>Serial</th><th nowrap>GeoIP</th></tr>\n");

interfaceId = 0
while ntop.getNextHost(interfaceId):
    geo = host.geoIP()
    country = geo.get('country_name', '')
    city = geo.get('city', '')

    ntop.sendString("<tr><td align=right>"+host.ethAddress()+"</td>"
                    +"<td align=right>"+host.ipAddress()+"</td>"
                    +"<td align=right>"+host.hostResolvedName()+"</td>"
                    +"<td align=center>"+host.numHostSessions()+"</td>"
                    +"<td align=center>"+host.totContactedSentPeers()+"</td>"
                    +"<td align=right>"+host.fingerprint()+"</td>"
                    +"<td align=center>"+host.serial()+"</td>"
                    +"<td align=center nowrap>"+city+" "+country+"</td>"
                    +"</tr>\n");
    
ntop.sendString("</table></center>\n");

ntop.printHTMLFooter();

