# Burton@ntopSupport.html
# Read a page on stdin and insert the ntop menu ssi's

BEGIN {
}

/<\/head>/ {
  i=index($0, "</head>")
  if(i>1) {
    print substr($0, 1, i-1)
    $0 = substr($0, i)
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
