# Import modules for CGI handling
import cgi, cgitb
import ntop

# Parse URL
cgitb.enable();

form = cgi.FieldStorage();
hello = form.getvalue('hello', default="world")

ntop.printHTMLHeader('Hello World', 1, 0)
ntop.sendString("Hello World: '"+hello+"'")
