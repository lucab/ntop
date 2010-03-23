import ntop;
import fastbit;
import pprint;

# Import modules for CGI handling
import cgi, cgitb

# Parse URL
cgitb.enable();


#########

form = cgi.FieldStorage();

ntop.printHTMLHeader("fastbit", 1, 1)

partition = form.getvalue('partition', default="/tmp/2010/03/23/14/45")
select = form.getvalue('select', "L4_SRC_PORT, L4_DST_PORT")
limit = form.getvalue('limit', 100);
where = form.getvalue('where', "L4_SRC_PORT > 0")

try:
    res = fastbit.query(partition, select, where, limit)
except:
    res = {}

ntop.sendString("<pre>")

pprint.pprint(res)
ntop.sendString("</pre>")
ntop.printHTMLFooter()
