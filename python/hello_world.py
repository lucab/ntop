import ntop;
import host;

ntop.sendHTTPHeader(0);
ntop.printHTMLHeader("Welcome to ntop+Python");

ntop.sendString("<center><table border>\n");
ntop.sendString("<tr><th>MAC Address</th><th>IP Address</th></tr>\n");

while ntop.getNextHost(0):
    ntop.sendString("<tr><td align=right>"+host.ethAddress()+"</td><td align=right>"+host.ipAddress()+"</td></tr>\n");
    
ntop.sendString("</table></center>\n");

ntop.printHTMLFooter();
