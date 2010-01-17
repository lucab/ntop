# Import modules for CGI handling
import cgi, cgitb

# Parse URL
cgitb.enable();

form = cgi.FieldStorage();
hello = form.getvalue('hello', default="world")


print "HTTP/1.0 200 OK"
print "Content-type: text/html\n"


print "Hello World: '"+hello+"'"
