# ntop - Burton M. Strauss III - Dec2004
BEGIN {
    print "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">"
    print "<html>"
    print "<head>"
    print "<!--meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" -->"
    print "<meta http-equiv=\"Content-Style-Type\" content=\"text/css\">"
    print "<meta http-equiv=\"Window-target\" content=\"_top\">"
    print "<meta name=\"description\" content=\"ntop (http://www.ntop.org) FAQ file.\">"
    print "<meta name=\"author\" content=\"ntop\">"

    while (getline < "version.c" > 0) {
        if($3 == "version") {
            gsub(/["; ]/, "", $5) 
            print "<meta name=\"generator\" content=\"ntop " $5 "\">"
        }
    }

    print "<title>ntop FAQ</title>"

    print "<script SRC=\"/functions.js\" TYPE=\"text/javascript\" LANGUAGE=\"javascript\"></script>"
    print "<script language=\"JavaScript\" SRC=\"/JSCookMenu.js\"></script>"
    print "<link rel=\"stylesheet\" href=\"/style.css\" TYPE=\"text/css\">"
    print "<link rel=\"stylesheet\" href=\"/theme.css\" TYPE=\"text/css\">"
    print "<script language=\"JavaScript\" src=\"/theme.js\"></script>"
    print "<script language=\"JavaScript\"><!--"

      print "var ntopMenu ="
      print "["
      print "	[null,'About',null,null,null,"
      print "		[null,'What is ntop?','/aboutNtop.html',null,null],"
      print "		[null,'Show Configuration','/info.html',null,null],"
      print "		[null,'Credits','/Credits.html',null,null],"
      print "		[null,'Man Page','/ntop.html',null,null],"
      print "		['<IMG SRC=/help.png>','Help','/ntophelp.html',null,null],"
      print "		['<IMG SRC=/bug.png>','Report a Problem','/ntopProblemReport.html',null,null],"
      print "		],"
      print "	[null,'Summary',null,null,null,"
      print "		[null,'Traffic','/trafficStats.html',null,null],"
      print "		[null,'Hosts','/hostsInfo.html',null,null],"
      print "		[null,'Network Load','/thptStats.html',null,null],"
      print "		[null,'ASN Info','/asList.html',null,null],"
      print "		[null,'VLAN Info','/vlanList.html',null,null],"
      print "		[null,'Network Flows','/NetFlows.html',null,null],"
      print "		],"
      print "   [null,'All Protocols',null,null,null,"
      print "           [null,'Traffic','sortDataProtos.html',null,null],"
      print "           [null,'Throughput','sortDataThpt.html',null,null],"
      print "           [null,'Activity','dataHostTraffic.html',null,null],"
      print "           ],"
      print "	[null,'IP',null,null,null,"
      print "		[null,'Summary',null,null,null,"
      print "				[null,'Traffic','/sortDataIP.html',null,null],"
      print "				[null,'Multicast','/multicastStats.html',null,null],"
      print "				[null,'Internet Domain','/domainStats.html',null,null],"
      print "				[null,'Distribution','/ipProtoDistrib.html',null,null],"
      print "		],"
      print "		[null,'Traffic Directions',null,null,null,"
      print "				[null,'Local to Local','/IpL2L.html',null,null],"
      print "				[null,'Local to Remote','/IpL2R.html',null,null],"
      print "				[null,'Remote to Local','/IpR2L.html',null,null],"
      print "				[null,'Remote to Remote','/IpR2R.html',null,null],"
      print "		],"
      print "		[null,'Local',null,null,null,"
      print "				[null,'Routers','/localRoutersList.html',null,null],"
      print "				[null,'Ports Used','/ipProtoUsage.html',null,null],"
      print "				[null,'Active TCP Sessions','/NetNetstat.html',null,null],"
      print "				[null,'Host Fingerprint','/localHostsFingerprint.html',null,null],"
      print "				[null,'Host Characterization','/localHostsCharacterization.html',null,null],"
      print "				[null,'Local Matrix','/ipTrafficMatrix.html',null,null],"
      print "		],"
      print "	],"
      print "	[null,'Media',null,null,null,"
      print "		[null,'Fibre Channel',null,null,null,"
      print "				[null,'Traffic','/FcData.html',null,null],"
      print "				[null,'Throughput','/FcThpt.html',null,null],"
      print "				[null,'Activity','/FcActivity.html',null,null],"
      print "				[null,'Hosts','/FcHostsInfo.html',null,null],"
      print "				[null,'Traffic Per Port','/FcShowStats.html',null,null],"
      print "				[null,'Sessions','/FcSessions',null,null],"
      print "				[null,'VSANs','/vsanList.html',null,null],"
      print "				[null,'VSAN Summary','/vsanDistrib.html',null,null],"
      print "		],"
      print "		[null,'SCSI Sessions',null,null,null,"
      print "				[null,'Bytes','/ScsiBytes.html',null,null],"
      print "				[null,'Times','/ScsiTimes.html',null,null],"
      print "				[null,'Status','/ScsiStatus.html',null,null],"
      print "				[null,'Task Management','/ScsiTMInfo.html',null,null],"
      print "		],"
      print "	],"
      print "	[null,'Admin',null,null,null,"
      print "		[null,'Plugins','/showPlugins.html',null,null],"
      print "		[null,'Switch NIC','/switch.html',null,null],"
      print "		['<IMG SRC=/lock.png>','Configure',null,null,null,"
      print "			['<IMG SRC=/lock.png>','Startup Options','/configNtop.html',null,null],"
      print "			['<IMG SRC=/lock.png>','Packet Filter','/changeFilter.html',null,null],"
      print "			['<IMG SRC=/lock.png>','Reset Stats','/resetStats.html',null,null],"
      print "			['<IMG SRC=/lock.png>','Web Users','/showUsers.html',null,null],"
      print "			['<IMG SRC=/lock.png>','Protect URLs','/showURLs.html',null,null],"
      print "		],"
      print "		['<IMG SRC=/lock.png>','Shutdown','/shutdown.html',null,null],"
      print "	],"
      print "	[null,'Utils',null,null,null,"
      print "		[null,'Data Dump','/dump.html',null,null],"
      print "		[null,'View Log','/viewLog.html',null,null]"
      print "		]"
      print "];"

    print "--></script>"

    print "</head>"
    print "<body link=\"blue\" vlink=\"blue\">"

    print "<table border=\"0\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\">"
    print "<tr><td colspan=\"2\" align=\"left\"><img src=\"ntop_logo.gif\"></td></tr>"
    print "<tr><th class=\"leftmenuitem\">"
    print "<div id=ntopMenuID>xxx</div>"
    print "<script language=\"JavaScript\"><!--"
    print "	cmDraw ('ntopMenuID', ntopMenu, 'hbr', cmThemeOffice, 'ThemeOffice');"
    print "--></script>"
    print "</th><th class=\"leftmenuitem\" align=\"right\">(C) 1998-2004 - <a href=\"mailto:deri@ntop.org\" title=\"Email Luca\">L. Deri</a>&nbsp;&nbsp;</th></tr>"
    print "</table>"
    print "<p>&nbsp;</p>"

    print "<h1>ntop FAQ...</h1>"
    print "<p>This is an unsophisticated, automated conversion of the source file, docs/FAQ into html."
    print "Please report problems to the ntop-dev mailing list."
    print "But remember, it's not about making it look good, it's about making the content available.</p>"
    print "<hr>"
    pastHeader="No"
    pclose="</p>"
    lines=0
    allDash=0
    allEquals=0
    header=0
    empty1=0
    empty2=0
    section=0
    q=0
    a=0
    text=0
    pre=0
    updated=0
    added=0
}

{
    lines++
    sub(/[\r\n]$/, "")
}

/^\-+$/ { 
    allDash++
    pastHeader="Yes"
    next
}

/^=+$/ { 
    allEquals++
    next
}

/^\-\-\-\-\-/ {
    gsub(/^\-*/, "", $0)
    gsub(/\-*$/, "", $0)
    print "<h2>" $0 "</h2>"
    next
}

pastHeader == "No" {
    header++
    next
}

$0 == "" {
    empty1++
    if (pclose != "") { print pclose }
    pclose=""
    next
}

/^ +$/ {
    empty2++
    if (pclose != "") { print pclose }
    pclose=""
    next
}

/^Section/ {
    section++
    if (pclose != "") { print pclose }
    pclose=""
    print "<h2>" $0 "</h2>"
    next
}

$1 == "(Added" {
    added++
    if (pclose != "") { print pclose }
    pclose=""
    print "<center><i>" $0 "</i></center>"
    next
}

$1 == "(Updated" {
    updated++
    if (pclose != "") { print pclose }
    pclose=""
    print "<center><i>" $0 "</i></center>"
    next
}

/^[Qq]([0-9]*[\(\)abc]*)?\. / {
    q++
    if (pclose != "") { print pclose }
    print "<br>"
    print "<p>"
    pclose="</p>"
    print "<b>" $1 "</b>&nbsp;"
    $1 = ""
    print $0
    next
}

/^[Aa]\. / {
    a++
    if (pclose != "") { print pclose }
    print "<p>"
    pclose="</p>"
    print "<b>" $1 "</b>&nbsp;"
    $1 = ""
    print $0
    next
}

(substr($0, 1, 3) == "   " && substr($0, 4, 1) != " ") {
    text++
    if (pclose == "") {
        print "<p>"
        pclose="</p>"
    }
    print $0
    next
}

{ 
    pre++
    if (pclose != "</pre>") {
        print pclose
        print "<pre>"
        pclose="</pre>"
    }
    print $0
    next
}

END {
    if (pclose != "") { print pclose }
    printf("<!-- Total Lines........ %5d -->\n\n" \
           "<!-- (skipped) --s...... %5d -->\n" \
           "<!-- (skipped) ==s...... %5d -->\n" \
           "<!-- (skipped) header... %5d -->\n" \
           "<!-- empty (\"\")......... %5d -->\n" \
           "<!-- empty (//)......... %5d -->\n" \
           "<!-- Sections........... %5d -->\n" \
           "<!-- Q:................. %5d -->\n" \
           "<!-- A:................. %5d -->\n" \
           "<!-- Normal text........ %5d -->\n" \
           "<!-- Preformatted text.. %5d -->\n" \
           "<!-- Updated.xxmmmyyyy.. %5d -->\n" \
           "<!-- Added.xxmmmyyyy.... %5d -->\n" \
           "<!-- ...........TOTAL... %5d -->\n",
                lines,
                allDash,
                allEquals,
                header,
                empty1,
                empty2,
                section,
                q,
                a,
                text,
                pre,
                updated,
                added,
                (allDash + allEquals + header + empty1 + empty2 + section + q + a + text + pre + updated + added))
                
    print "</body>"
    print "</html>"
}

#Q. What is ntop?
#A. ntop is an open source network top - the official website can be found at
#   http://www.ntop.org/

