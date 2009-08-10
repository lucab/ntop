import ntop;
import host;

print 'Hello';

ntop.sendHTTPHeader(0);
ntop.printHTMLHeader("Luca");

ntop.getFirstHost(0);
ntop.sendString(host.ethAddress());

while ntop.getNextHost(0):
    ntop.sendString(host.ethAddress()+"/"+host.ipAddress()+"<br>");

ntop.sendString('Hello');
ntop.printHTMLFooter();
