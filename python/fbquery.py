 # -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 #              __ _
 #             / _| |__   __ _ _   _  ___ _ __ _   _
 #            | |_| '_ \ / _` | | | |/ _ \ '__| | | |
 #            |  _| |_) | (_| | |_| |  __/ |  | |_| |
 #            |_| |_.__/ \__, |\__,_|\___|_|   \__, |
 #                          |_|                |___/
 #
 #                       Copyright (C) 2009
 #                    Luca Deri <deri@ntop.org>
 #             Valeria Lorenzetti <lorenzetti@ntop.org>
 #
 #                     http://www.ntop.org/
 #
 # -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 #
 # This program is free software; you can redistribute it and/or modify
 # it under the terms of the GNU General Public License as published by
 # the Free Software Foundation; either version 2 of the License, or
 # (at your option) any later version.
 #
 # This program is distributed in the hope that it will be useful,
 # but WITHOUT ANY WARRANTY; without even the implied warranty of
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 # GNU General Public License for more details.
 #
 # You should have received a copy of the GNU General Public License
 # along with this program; if not, write to the Free Software Foundation,
 # Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 #

import ntop;
import host;

# Import modules for CGI handling
import cgi, cgitb

# Import module for execute fbquery
import subprocess
import string, sys
import csv


#
# Parse URL
#
form = cgi.FieldStorage()

#
# fbquery path and database
#
fb_binary = ntop.getPreference ("fastbit.fbquery");
fb_partition = ntop.getPreference ("fastbit.partition");

#
# fbquery input parameter
#
fb_select = form.getvalue('select')
fb_where = form.getvalue('where')

#
# fbquery output format
#
fb_output = form.getvalue('output')

if fb_output == "PLAIN":
    output = "-P"
elif fb_output == "XML":
    output = "-X"
else:
    output = ""

#
# Rows limit number in fbquery output
#
fb_limit = form.getvalue('limit', default="50")


# Debug
fb_submit = form.getvalue('submit')

#
# Check for mandatory ntop preferences
#
if not fb_binary or not fb_partition:

    ntop.printHTMLHeader("fbquery");
    ntop.sendString ("<center>")
    ntop.sendString ("<font color=red>Warning: missing mandatory ntop preferences!</font><br><br><br>")
    ntop.sendString ("This page is not operational when <b>fastbit.fbquery</b> and <b>fastbit.partition</b> "
                     "preferences are missing.<br><br>")
    ntop.sendString ("You can set these two ntop preferences from <i>Admin/Configure/Preferences</i> menu "
                     "as described in the table below.<br><br>")
    # Table
    ntop.sendString ("<table border=1 cellspacing=0 cellpadding=2>")
    ntop.sendString ("<tr><th align=center bgcolor=#f3f3f3>Preference</th>")
    ntop.sendString ("<th align=center bgcolor=#f3f3f3>Value to Configure</th></tr>")

    # fastbit.fbquery
    ntop.sendString ("<tr><th align=left bgcolor=#f3f3f3>fastbit.fbquery</th>")
    ntop.sendString ("<td align=left bgcolor=white><i>Absolute pathname of fbquery binary</i> "
                     "&nbsp;&nbsp;<small>(e.g. /usr/local/bin/fbquery)</small></td></tr>")

    # fastbit.partition
    ntop.sendString ("<tr><th align=left bgcolor=#f3f3f3>fastbit.partition</th>")
    ntop.sendString ("<td align=left bgcolor=white><i>Absolute pathname of fastbit database</i> "
                     "&nbsp;&nbsp;<small>(e.g. /usr/local/network/database)</small></td></tr>")
    ntop.sendString ("</table></center>")

    # Exit
    ntop.sendString ("<br><br>")
    ntop.printHTMLFooter();
    sys.exit()


#
# Check for mandatory input
#
if not fb_where:

    ntop.printHTMLHeader("fbquery");
    ntop.sendString ("<center>")

    if fb_submit:
        ntop.sendString ("<font color=red>Warning: you have submitted an empty or illegal query!</font><br><br><br>")

    # Form
    ntop.sendString ("<form name=input action=\"\" method=get>\n")
    ntop.sendString ("<table align=center>")
    ntop.sendString ("<tr><td><b>SELECT</b></td><td><input type=text name=select size=40></td></tr>")
    ntop.sendString ("<tr><td><b>FROM</b></td><td><input type=text name=from size=40 value="+fb_partition+"></td></tr>")
    ntop.sendString ("<tr><td><b>WHERE</b></td><td> <input type=text name=where size=40></td></tr>")
    ntop.sendString ("<input type=hidden name=output value=PLAIN>")
    ntop.sendString ("<input type=hidden name=submit value=yes>")
    ntop.sendString ("<tr><td colspan=2 align=center><input type=submit value=\"Query!\"></td></tr>")
    ntop.sendString ("</table></form>\n")
    ntop.sendString ("<br><br>")

    # How to
    ntop.sendString ("How to submit a query:<br><br>")
    ntop.sendString ("<table border=1 cellspacing=0 cellpadding=2>")
    ntop.sendString ("<tr><th align=center bgcolor=#f3f3f3>Field</th>")
    ntop.sendString ("<th align=center bgcolor=#f3f3f3>Value</th>")
    ntop.sendString ("<th align=center bgcolor=#f3f3f3>Example</th></tr>")

    ntop.sendString ("<tr><th align=left bgcolor=#f3f3f3>SELECT</th>")
    ntop.sendString ("<td align=left bgcolor=white>Comma separated column names</td>")
    ntop.sendString ("<td align=left bgcolor=white>IPV4_SRC_ADDR,L4_SRC_PORT,L4_DST_PORT</td></tr>")

    ntop.sendString ("<tr><th align=left bgcolor=#f3f3f3>FROM</th>")
    ntop.sendString ("<td align=left bgcolor=white>Absolute pathname of Fastbit directory to query</td>")
    ntop.sendString ("<td align=left bgcolor=white>/usr/local/network/database</td></tr>")

    ntop.sendString ("<tr><th align=left bgcolor=#f3f3f3>WHERE</th>")
    ntop.sendString ("<td align=left bgcolor=white>Query conditions to satisfy [mandatory]</td>")
    ntop.sendString ("<td align=left bgcolor=white>L4_SRC_PORT>80</td></tr>")
    ntop.sendString ("</table>")

    # Exit
    ntop.printHTMLFooter();
    sys.exit()


#
# Execute fbquery
#

ntop.printHTMLHeader("fbquery");

if fb_select:

    pipe = subprocess.Popen ([fb_binary, "-c", fb_select, "-d", fb_partition, "-q", fb_where, output, "-L", fb_limit],
                                 stdout = subprocess.PIPE, stderr = subprocess.PIPE)

    # fbquery output
    result = pipe.stdout.read()

    # Parsing query result and fill the HTML table
    ntop.sendString ("<center><table border=1 cellspacing=0 cellpadding=2>")

    # Rows list
    rows = result.split ("\n")

    # First row became the table header
    headers = rows[0].split ("|")

    #
    # TABLE HEADER
    #
    ntop.sendString ("<tr>")
    for i in range (0, len (headers)):
        ntop.sendString ("<th align=center bgcolor=#f3f3f3>" + headers [i] + "</th>")
    ntop.sendString ("</tr>")

    #
    # TABLE DATA
    #
    for j in range (1, len (rows) - 1):

        # Split each rows
        r = rows[j].split ("|")

        ntop.sendString ("<tr>")
        for k in range (0, len (r)):
            ntop.sendString ("<td align=left bgcolor=white>" + r [k] + "</td>")
        ntop.sendString ("</tr>")

    ntop.sendString ("</table></center>")

else:
    pipe = subprocess.Popen ([fb_binary, "-d", fb_partition, "-q", fb_where, "-L", fb_limit],
                             stdout = subprocess.PIPE, stderr = subprocess.PIPE)

    ntop.sendString (pipe.stdout.read())
    ntop.sendString (pipe.stderr.read())


ntop.printHTMLFooter();
