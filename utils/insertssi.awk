# Burton@ntopSupport.html
# Read a page on stdin and insert the ntop menu ssi's

# v 1.0 March 2005 initial release
# v 1.1 Apr   2005 Add style.css

# Distributed as part of ntop, http://www.ntop.org

 # -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
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
 # -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 # 

BEGIN {
  stylecss="n"
}

/style\.css/ {
  stylecss="y"
}

/<\/head>/ {
  i=index($0, "</head>")
  if(i>1) {
    print substr($0, 1, i-1)
    $0 = substr($0, i)
  }
  if(stylecss == "n") {
    print "<!-- Added by insertssi -->"
    print "<link rel=stylesheet href=\"/style.css\" type=\"text/css\">"
  }
  print "<!--#include virtual=\"/menuHead.html\" -->"

}

/<body/ {
  i=index($0, "<body")
  if(i>1) {
    print substr($0, 1, i-1)
    $0 = substr($0, i)
  }

  i=index($0, ">")
  if(i>1) {
    print substr($0, 1, i)
    $0 = substr($0, i+1)
    print "<!--#include virtual=\"/menuBody.html\" -->"
    if($0 == "") { next }
  } else {
    $0=$0 "<p><b>WARNING</b>: Unable to insert menuBody SSI</p>"
  }
}

{
  print $0
}

END {
}
