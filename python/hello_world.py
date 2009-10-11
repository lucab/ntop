import ntop;
import host;

# Import modules for CGI handling
import cgi, cgitb

# Parse URL
cgitb.enable();

form = cgi.FieldStorage();

fingerprint = form.getvalue('fingerprint', default="fbquery")

ntop.printHTMLHeader("Welcome to ntop+Python");


serials = {};

while ntop.getNextHost(0):
    if host.ipAddress() != "":
        serials[host.ipAddress()] = host.serial();


ntop.sendString("<center><table border>\n");
ntop.sendString("<tr><th>MAC Address</th><th>IP Address</th><th>Name</th><th># Sessions</th><th># Contacted Peers</th><th>Fingerprint</th><th>Serial</th></tr>\n");

while ntop.getNextHost(0):
    ntop.sendString("<tr><td align=right>"+host.ethAddress()+"</td>"
                    +"<td align=right>"+host.ipAddress()+"</td>"
                    +"<td align=right>"+host.hostResolvedName()+"</td>"
                    +"<td align=center>"+host.numHostSessions()+"</td>"
                    +"<td align=center>"+host.totContactedSentPeers()+"</td>"
                    +"<td align=right>"+host.fingerprint()+"</td>"
                    +"<td align=center>"+host.serial()+"</td>"
                    +"</tr>\n");
    
ntop.sendString("</table></center>\n");

ntop.printHTMLFooter();

