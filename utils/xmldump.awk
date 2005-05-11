## ntop xml output generator -- tools

# Written by and copyright (c) 2002, Burton M. Strauss III

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

# This tool is part of the ntop xml output system, but it is in fact
# not normally executed by persons compiling ntop.

# It is designed for the developers of ntop to create various .inc files
# used by xmldumpPlugin.c.  It should be run after any changes to globals.h or
# ntop.h

# Note that it IS perfectly safe to run, since you should NEVER be editing
# the generated .inc files by hand.

#  Usage:   awk -f xmldump.awk xxx.h

#  This script is designed to extract structured comments from ntop .h files 
#  to create c code in the .inc files which are the xml (gdome) statements 
#  for xmldumpPlugin.c to build the DOM structure.

#  Beware - between this routine and the convenience functions in xmldumpPlugin.c, 
#  A LOT of complexity is hidden.

# The "structured comment language":

#/*XMLNOTE ...whatever... */
#  --Is a comment, but one that we are indicating is related to the xml stuff.
#
#/*XMLSTRUCT structurename [additional vars] */
#  --Causes both a forward declaration and normal code block to be generated 

#/*XMLDEFINEBEGIN filename */
#/*XMLDEFINE name value */
#/*XMLDEFINEEND */
#  --Creates a file with #define lines

#/*XMLSECTIONBEGIN filename parent prefix extrabufs */
#  --Causes new file to be created, and to start creating xml statements under
#    the node [el]parent, pulling data from prefix.whatever
#
#    So the typical  /*XMLSECTIONBEGIN xmlmyglobals.inc Globals myGlobals */
#    starts writing to xmlmyglobals.inc, using elGlobals as the base node and
#    prefixing variables by myGlobals.   
#
#/*XMLSECTIONEND [name] */
#  --Ends echo to section...
#
#/*XMLPARENT parent */
#  --Causes new parent to be used... keeping name and prefix.
#
#/*XMLPREFIX prefix */
#  --Causes new prefix to be used... keeping name and parent.

# The processing statement is:
#
#/*XML type[:format] item[:itemname] childof[:result] "description" */
#
#   Types:
#           b        noyes
#           h        hex (0x....)
#           e        empty
#           n[:fmt]  numeric
#           nc:[fmt] numeric constant (e.g. #define) ... NO PREFIX!
#           s        string
#           sc       string constant (e.g. #define) ... NO PREFIX!
#           si       string index (special form of string)
#           x        ignore
#           *        special (inline) code
#
#/*XMLEXISTS nodename ... */
#  --Tells script that nodename exists ... loads it into nodes[]
#
#/*XMLFOR var initial test [operand] */
#         2   3       4    5...      NF
#      
#       XMLFOR i 0 "a[i] != NULL" ->  for (i=0; a[i] != NULL; i++)
#       XMLFOR i 0 1              ->  for (i=0; i<1; i++)
#       XMLFOR i 0 1 <=           ->  for (i=0; i<=1; i++)
#
#/*XMLROF */
#  --creates closing } for XMLFOR
#
#/*XMLIF test */
#/*XMLELSE */
#/*XMLFI */
#  -- becomes if (test) { ...
#             }
#
#/*XMLSWITCH value */
#/*XMLCASE value */
#/*XMLHCTIWS */
#  -- becomes switch (value) {
#               case value: ...; break;
#             }
#
#/*XMLINLINE name   
#   ... source ... with $x variables substituted ...
#XML*/
#
#/*XMLLINKEDLIST type name base link parent
#   ... follows a linked list creating entries of 'type'
#

function insert_nodes(value, tag) {
     if (debug != "") printf("    /*XMLNOTE insert_node(%s)=%s\n", value, tag)
     if (value != "") {
         nodes[value] = tag
     }
}

function process_parent() {
     if (parent == "root") {
         parentnodename=parent
     } else if (parent == "parent") {
         parentnodename=parent
     } else {
         parentnodename="el" toupper(substr(parent, 1, 1)) substr(parent, 2)
     }
     if (parent in nodes) {
     } else {
         if (debug != "") printf("    /*XMLNOTE Generating node %s, child of root\n", parent)
         printf("/* *via XMLPARENT********************************Assume root* */\n" \
                "%s%s = newxmlna(root, \"%s\");\n\n",
                indent,
                parentnodename,
                parent) >>outputname
         insert_nodes(parent, "XMLPARENT")
     }
}

function process_prefix() {
     if (substr(prefix, length(prefix)-1) == "->") {
         connect=""
         stripedprefix=substr(prefix, 1, length(prefix)-2)
     } else if (substr(prefix, length(prefix)) == ".") {
         connect=""
         stripedprefix=substr(prefix, 1, length(prefix)-1)
         sub(/\[i.*\]/, "", stripedprefix);
     } else {
         if (prefix != "myGlobals") {
             connect="->"
         } else {
             connect="."
         }
         stripedprefix=prefix
     }
}

BEGIN {
    # export debug=anything to turn on debug
    debug=ENVIRON["XMLDUMPDEBUG"]

    # Start off dumping to the bit bucket.
    outputname="/dev/null"

    print "xmldump.awk running..."
    lines=0

    parent="root"

    nodes["root"]    = "Default"
    nodes["parent"]  = "Default"

    workNodePrefix="elWork"

    #
    # Preset the stuff we "know"...
    #
    type_macroname_conversion["b"]              = "newxml_simplenoyes"
    type_macroname_conversion["h"]              = "newxml_simplehex"
    type_macroname_conversion["e"]              = "newxml_empty"
    type_macroname_conversion["n"]              = "newxml_simplenumeric"
    type_macroname_conversion["nc"]             = "newxml_namednumeric"
    type_macroname_conversion["f"]              = "newxml_simplefloat"
    type_macroname_conversion["s"]              = "newxml_smartstring"
    type_macroname_conversion["sc"]             = "newxml_namedstring"
    type_macroname_conversion["*"]              = "special-inline-code"
    type_macroname_conversion["SPECIAL1"]       = "special-output-coding"

    #
    # Special conversions...
    #
    type_macroname_conversion["tcp_seq"]        = "newxml_namednumeric"
    macroformat["tcp_seq"]                      = "u"

    # Skip the (item, value) pair on the call, also 
    #   Force an empty :result to itemname
    type_nonvalue_node["e"]                     = "yes"

    # Don't prepend the "prefix" from XMLSECTIONBEGIN / XMLPREFIX on these 
    # Generate <name constantname=value> instead of the <item= value= >
    type_constant_item["nc"]                    = "yes"
    type_constant_item["sc"]                    = "yes"

    # These append and (index, value) set to the parameters (value is the index to append)
    ##type_appendindex["hosttraffic"]             ="j"
    ##type_appendindex["si"]                      ="i"

    #
    # Load a list of stuff defined in xmldumpPlugin.c
    #
    system("grep '^ *#define *newxml_' xmldumpPlugin.c >/tmp/xmldump1")
    while (getline < "/tmp/xmldump1" > 0) {
        i=index($2, "(")
        macro=substr($2, 1, i-1)
        gsub(/newxml_/, "", macro)
        type_macroname_conversion[macro]    = "newxml_" macro
    }
    system("grep '^GdomeElement \\* newxml_' xmldumpPlugin.c > /tmp/xmldump2")
    while (getline < "/tmp/xmldump2" > 0) {
        i=index($3, "(")
        functionname=substr($3, 1, i-1)
        gsub(/newxml_/, "", functionname)
        type_macroname_conversion[functionname]    = "newxml_" functionname
    }

    system("rm -f /tmp/xmldump[12]")

    printf("/* Created by xmldump.awk\n" \
           " *\n" \
           " * part of and licensed the same as ntop, http://www.ntop.org\n" \
           " *\n" \
           " * WARNING: Changes made here will be lost the next time this\n" \
           " * file is recreated, which can happen automatically during\n" \
           " * a 'make'.\n" \
           " *\n" \
           " */\n\n\n") > "xml_s_simple_forward.inc"
    printf("/* Created by xmldump.awk\n" \
           " *\n" \
           " * part of and licensed the same as ntop, http://www.ntop.org\n" \
           " *\n" \
           " * WARNING: Changes made here will be lost the next time this\n" \
           " * file is recreated, which can happen automatically during\n" \
           " * a 'make'.\n" \
           " *\n" \
           " */\n\n\n") > "xml_s_simple.inc"

    indent = "    "
    inlineline = 0
}

# Count input lines...
{
    lines++
}

$1 == "/*XMLNOTE" {
#/*XMLNOTE ... whatever ... */
     # This is just a note to ourselves ... ignore it...
     if (debug != "") print "    " $0
     next
}


$1 == "/*XMLSTRUCT" {
#  --Causes both a forward declaration and normal code block to be generated 
     if (debug != "") print "    " $0

     structure = $2
     sname = tolower($2)

     printf("GdomeElement * newxml_%s(GdomeElement * parent,\n" \
            "                       char * nodename,\n" \
            "                       %s * input,\n" \
            "                       char * description);\n\n",
            sname,
            structure) >> "xml_s_simple_forward.inc"

     additionalvars = ""
     for (i=3; i<NF; i++) {
       additionalvars = additionalvars ", *el" $i
     }      

     printf("GdomeElement * newxml_%s(GdomeElement * parent,\n" \
            "                       char * nodename,\n" \
            "                       %s * input,\n" \
            "                       char * description) {\n\n" \
            "    GdomeElement *elWork%s;\n" \
            "    GdomeException exc;\n\n" \
            "#if (XMLDUMP_DEBUG >= 3)\n" \
            "        traceEvent(CONST_TRACE_INFO, \"XMLDUMP_DEBUG: Starting newxml_%s\");\n" \
            "#endif\n\n" \
            "    /* Insert the generated block of code */\n" \
            "        #include \"xml_s_%s.inc\"\n\n" \
            "#if (XMLDUMP_DEBUG >= 3)\n" \
            "        traceEvent(CONST_TRACE_INFO, \"XMLDUMP_DEBUG: Ending newxml_%s\");\n" \
            "#endif\n\n" \
            "    return elWork;\n" \
            "}\n\n",
            sname,
            structure,
            additionalvars,
            sname,
            sname,
            sname) >> "xml_s_simple.inc"

     type_macroname_conversion[sname] = "newxml_" sname

     next
}

$1 == "/*XMLDEFINEBEGIN" {
     # Handle (close) prior section...
     if ( (outputname != "") && (outputname != "/dev/null") ) {
         if (debug != "") printf("    /*XMLNOTE Closing %s */\n", outputname)
         print "" >>outputname
         close(outputname)
     }

     sectionhead=""
     outputname = $2
     if (outputname in sections) {
         if (debug != "") print "    /*XMLNOTE Resuming " outputname " */"
     } else {
         sectionhead="y"
         if (debug != "") print "    /*XMLNOTE Begining " outputname " */"
         sections[outputname]="Yes"
         printf("/* Created by xmldump.awk\n" \
                " *\n" \
                " * part of and licensed the same as ntop, http://www.ntop.org\n" \
                " *\n" \
                " * WARNING: Changes made here will be lost the next time this\n" \
                " * file is recreated, which can happen automatically during\n" \
                " * a 'make'.  Y'all been warned, now!\n" \
                " *\n" \
                " */\n\n\n") >outputname
     }
     next
}

$1 == "/*XMLDEFINE" {
  print "#define " $2 " " $3 >>outputname
  next
}

$1 == "/*XMLDEFINEEND" {
     if (outputname != "") {
         if (debug != "") print "    /*XMLNODE Suspending " outputname " */"
         print "" >>outputname
         close(outputname)
     }
     outputname = "/dev/null"
     next
} 

$1 == "/*XMLSECTIONBEGIN" {
     # Handle (close) prior section...
     if ( (outputname != "") && (outputname != "/dev/null") ) { 
         if (debug != "") printf("    /*XMLNOTE Closing %s */\n", outputname)
         print "" >>outputname
         close(outputname) 
     }


     sectionhead=""
     outputname = $2
     if (outputname in sections) {
         if (debug != "") print "    /*XMLNOTE Resuming " outputname " */"
     } else {
         sectionhead="y"
         if (debug != "") print "    /*XMLNOTE Begining " outputname " */"
         sections[outputname]="Yes"
         printf("/* Created by xmldump.awk\n" \
                " *\n" \
                " * part of and licensed the same as ntop, http://www.ntop.org\n" \
                " *\n" \
                " * WARNING: Changes made here will be lost the next time this\n" \
                " * file is recreated, which can happen automatically during\n" \
                " * a 'make'.  Y'all been warned, now!\n" \
                " *\n" \
                " */\n\n\n") >outputname
     }

     parent=$3
     process_parent()

     prefix     = $4
     process_prefix()

     printf("char buf[LEN_GENERAL_WORK_BUFFER]") >>outputname
     for(i=5; i<NF; i++) {
       printf(",\n             %s[LEN_GENERAL_WORK_BUFFER]", $i) >>outputname
     }
     printf(";\n\n") >>outputname
 
     if (sectionhead == "y") {
         if (stripedprefix != "myGlobals") {
             printf("    if (%s == NULL) { return NULL; };\n", stripedprefix) >>outputname
         }
         printf("    if (%s == NULL) { return NULL; };\n\n\n", parentnodename) >>outputname
     }

     printf("    memset(&buf, 0, sizeof(buf));\n") >>outputname
     for(i=5; i<NF; i++) {
       printf("    memset(&%s, 0, sizeof(%s));\n", $i, $i) >>outputname
     }
     printf("\n") >>outputname
 
     next
}

$1 == "/*XMLPARENT" {

     parent=$2
     process_parent()
     next
}

$1 == "/*XMLPREFIX" {
     prefix     = $2
     process_prefix()
     next
}

$1 == "/*XMLSECTIONEND" {
     if (outputname != "") { 
         if (debug != "") print "    /*XMLNODE Suspending " outputname " */"
         print "" >>outputname
         close(outputname) 
     }
     outputname = "/dev/null"
     next
}

$1 == "/*XMLEXISTS" {
     for (i=2; i<NF; i++) {
         if ($i == "*/") { break }
         if ( ($i != "") && ($i != "root") && ($1 != "parent") ) {
             if (debug != "") print "    /*XMLNOTE XMLEXISTS - marking node " $i " */"
              insert_nodes($i, "XMLEXISTS")
         }
     }
     nodename=""
     next
}

$1 == "/*XMLINLINE" {
     inlinename = $2
     inlinecode_start[inlinename] = inlineline
     while (getline > 0) {
         if ($1 == "XML*/") { break }
         inlinecode[inlineline++] = $0
     }
     inlinecode_end[inlinename] = inlineline
}

$1 == "/*XMLLINKEDLIST" {
     type=$2
     name=$3
     base=$4
     link=$5
     parent=$6
     
     printf("%s{ GdomeElement *llWork;\n" \
            "%s  int indexLL = 0;\n" \
            "%s  %s *ptr = myGlobals.%s;\n" \
            "%s  while (ptr != NULL) {\n" \
            "%s    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), \"%%d\", indexLL++);\n" \
            "%s    llWork = newxml(el%s, \"index\", \"value\", buf, \"\");\n" \
            "%s    newxml_%s(llWork, \"%s\", ptr, \"\");\n" \
            "%s    ptr = ptr->%s;\n" \
            "%s} }\n",
            indent,
            indent,
            indent, type, base,
            indent,
            indent,
            indent, parent,
            indent, tolower(type), type,
            indent, link,
            indent) >>outputname

     next
}

# EXPERIMENTAL
$1 == "/*XMLPTR" {
     next
}

$1 == "/*XMLSET" {
     next
}

$1 == "/*XMLWHILE" {

     if (substr($2, 1, 1) == "\"") {
         compare = $2
         for (i=3; i<NF; i++) {
             compare = compare " " $i
         }  
         gsub(/\"/, "", compare)
     } else if ($3 == "*/") {
         compare = $2 "<" $3
     } else {
         compare = $2 " " $3 " " $4
     } 

     printf("%swhile (%s) {\n", indent, compare) >>outputname
     indent = indent "\t"
     next
}

(($1 == "/*XMLELIHE") || ($1 == "/*XMLELIHE*/")) {
     indent = substr(indent, 1, length(indent)-1)
     printf("%s} }\n\n", indent) >>outputname
     next
}

#END EXPERIMENTAL 

$1 == "/*XMLFOR" {

     var  = $2

     init = $2 "=" $3

     if (substr($4, 1, 1) == "\"") {
         compare = $4
         for (i=5; i<NF; i++) {
             compare = compare " " $i
         }
         gsub(/\"/, "", compare)
     } else if ($5 == "*/") {
         compare = $2 "<" $4
     } else {
         compare = $2 " " $5 " " $4
     }

     increment = $2 "++"

     printf("%s{ int %s;\n%s  for (%s; %s; %s) {\n", indent, var, indent, init, compare, increment) >>outputname
     indent = indent "\t"
     next
}

(($1 == "/*XMLROF") || ($1 == "/*XMLROF*/")) {
     indent = substr(indent, 1, length(indent)-1)
     printf("%s} }\n\n", indent) >>outputname
     next
}

$1 == "/*XMLIF" {
     test = $2
     for (i=3; i<=NF; i++) {
         if ($i == "*/") { 
             i=NF+1
         } else {
             test = test " " $i
         }
     }

     printf("%sif (%s) {\n", indent, test) >>outputname
     indent = indent "\t"
     next
}

(($1 == "/*XMLELSE") || ($1 == "/*XMLELSE*/")) {
     printf("%s} else {\n\n", indent) >>outputname
     next
}

(($1 == "/*XMLFI") || ($1 == "/*XMLFI*/")) {
     indent = substr(indent, 1, length(indent)-1)
     printf("%s}\n\n", indent) >>outputname
     next
}

$1 == "/*XMLSWITCH" {
     printf("%sswitch (%s) {\n", indent, $2) >>outputname
     indent = indent "\t"
     forceBreak="n"
     next
}

(($1 == "/*XMLCASE") || ($1 == "/*XMLCASE*/")) {
     if(forceBreak == "y") {
       printf("%s    break;\n", indent) >>outputname
     }
     if(tolower($2) == "default") {
       printf("%s  default:\n", indent) >>outputname
     } else {
       printf("%s  case %s:\n", indent, $2) >>outputname
     }
     if(tolower($3) == "withnext") {
       forceBreak="n"
     } else {
       forceBreak="y"
     }
     next
}    

(($1 == "/*XMLHCTIWS") || ($1 == "/*XMLHCTIWS*/")) {
     indent = substr(indent, 1, length(indent)-1)
     printf("%s}\n\n", indent) >>outputname
     inCase="n"
     next
}



substr($1, 1, 3) == "#if" {
     print "\n" $0 >>outputname
     next
}

substr($1, 1, 5) == "#else" {
     print $0 >>outputname
     next
}

substr($1, 1, 5) == "#elif" {
     print $0 >>outputname
     next
}

substr($1, 1, 6) == "#endif" {
     print $0 "\n" >>outputname
     next
}

$1 == "/*XML" {
#/*XML type[:format] item[!]itemname  childof[:result] "description" */
#$1    2             3                4                5...
     # Presets...
     gdomenode=""

     # Process fields...
     if ( (NF < 5) && ($2 != "x") && ($2 != "*") ) {
         printf("\n\n ERROR -- missing fields on following line:\n%5d. %s\n\n", lines, $0)
         next
     }

     if ((i=index($2, ":")) > 0) {
         typeflag = substr($2, 1, i-1)
         format   = substr($2, i+1)
     } else {
         typeflag = $2
         format   = ""
     }

     if ((i=index($3, "!")) > 0) {
         item    = substr($3, 1, i-1)
         itemname= substr($3, i+1)
     } else {
         item    = $3
         itemname= item
     }

     if ((i=index($4, ":")) > 0) {
         childof = substr($4, 1, i-1)
         result  = substr($4, i+1)
     } else {
         childof = $4
         result  = ""
     }

     description=$5
     for (i=6; i<NF; i++) {
         if ($i != "*/") {
             description = description " " $i
         }
     }

 # All parms read...
     f1 = typeflag (format == "" ? "" : ":") format 
     f2 = item (item == itemname ? "" : "!" itemname)
     f3 = childof  (result == "" ? "" : ":") result 
     processedline = sprintf("/*XML %-15s %-20s %-15s %s */", 
                                    f1, 
                                          f2,
                                                f3,
                                                      description)
     print indent processedline >>outputname
     if (debug > "1") { printf("    /*XMLNOTE input line is '%s' */\n", $0)
                        printf("    /*XMLNOTE processed as  '%s' */\n", processedline)
                        printf("\n    /*XMLNOTE RAW values: */\n")
                        printf("        /*XMLNOTE childof.........'%s' */\n", childof)
                        printf("        /*XMLNOTE description.....'%s' */\n", description)
                        printf("        /*XMLNOTE format..........'%s' */\n", format)
                        printf("        /*XMLNOTE item............'%s' */\n", item)
                        printf("        /*XMLNOTE itemname........'%s' */\n", itemname)
                        printf("        /*XMLNOTE result..........'%s' */\n", result)
                        printf("        /*XMLNOTE typeflag........'%s' */\n", typeflag)
     }

 # Errors and other reasons to ignore this...
     if (typeflag == "x") { 
	 if (debug != "") printf("    /*XMLNOTE Ignored: %s */\n", item)
	 next
     }
     if (result == "root") {
         if (debug != "") printf("    /*XMLNOTE ERROR resetting root node */\n")
         next
     } else if (result == "parent") {
         if (debug != "") printf("    /*XMLNOTE ERROR resetting parent node */\n")
         next
     }

 # Convenience conversions...
     if (typeflag == "char*") {
         typeflag="s"
     }

 # Cleanup, Tests and priority items...
     typeprefix=""
     if (typeflag == "*") {
     } else {
         while (substr(typeflag, 1, 1) == "*") {
             typeprefix=typeprefix "* "
             typeflag = substr(typeflag, 2)
         }
         if (substr(typeflag, 1, 1) == "&") {
             typeprefix=typeprefix "&"
             typeflag = substr(typeflag, 2)
         }
     }
     if (debug > "1") { printf("\n    /*XMLNOTE PROCESSED values: */\n")
                        printf("        /*XMLNOTE typeflag........'%s' */\n", typeflag)
                        printf("        /*XMLNOTE typeprefix......'%s' */\n", typeprefix)
     }
     if (item == ".") { 
         item = ""
         if (debug > "1") { printf("        /*XMLNOTE item............'%s' */\n", item) }
     }
     if (childof  == ".") { 
         childof  = ""
         if (debug > "1") { printf("        /*XMLNOTE childof.........'%s' */\n", childof) }
     }
     if (description == "*/") {
         description = ""
         if (debug > "1") { printf("        /*XMLNOTE description.....'%s' */\n", description) }
     }

 # Derived stuff...

     # What about the "item"? Just to clarify...
     #   item is the way the user named it (e.g. xyz) -- we don't use that past here
     #   itemname is how to refer to it in xml (xyz)
     #      Setting those is handled above, like all the other field splits
     #   itemref is how to refer to it in c (myGlobals.xyz)
     #   fieldname is the stripped version of itemname

     #   Cleanup itemname, stripping indexes, pointers, etc.
     while ((i=index(itemname, ".")) > 0) {
         itemname=substr(itemname, i+1)
     }
     while ((i=index(itemname, "->")) > 0) {
         itemname=substr(itemname, i+2)
     }
     if ((i=index(itemname, "_")) > 0) {
         itemname=substr(itemname, i+1)
     }
     if ((i=index(itemname, "[")) > 0) {
         itemname=substr(itemname, 1, i-1)
     }
     if ((i=index(itemname, "(")) > 0) {
         itemname=substr(itemname, 1, i-1)
     }
     if (debug > "1") { printf("        /*XMLNOTE itemname........'%s' (xml) */\n", itemname) }

     fieldname=itemname
     #   Cleanup fieldname, stripping indexes, pointers, etc.
     while ((i=index(fieldname, ".")) > 0) {
         fieldname=substr(fieldname, i+1)
     }
     while ((i=index(fieldname, "->")) > 0) {
         fieldname=substr(fieldname, i+2)
     }
     while ((i=index(fieldname, "&")) > 0) {
         fieldname=substr(fieldname, i+1)
     }
     while ((i=index(fieldname, "_")) > 0) {
         fieldname=substr(fieldname, i+1)
     }
     if ((i=index(fieldname, "[")) > 0) {
         fieldname=substr(fieldname, 1, i-1)
     }
     if (debug > "1") { printf("        /*XMLNOTE fieldname.......'%s' (stripped) */\n", fieldname) }

     #   Set itemref
     if (typeflag in type_constant_item) {
         itemref=item
     } else {
         if ( (substr(item, 1, 1) == ".") || 
              (substr(item, 1, 2) == "->") ) {
             itemref= prefix item
         } else if (substr(item, 1, 1) == "&") {
             item=substr(item, 2)
             itemref= "&" prefix connect item
#         } else if (prefix == "myGlobals") {
#             itemref= "&" prefix connect item
         } else if ( (index(item, ".") > 0) ||
                     (index(item, "->") > 0) ) {
             itemref=item
         } else if ( (index(item, "(") > 0) &&
                     (index(item, ")") > 0) ) {
             itemref=item
         } else {
             itemref= prefix connect item
         }
     }
     if (debug > "1") { printf("        /*XMLNOTE itemref.........'%s' (c) */\n", itemref) }

     if (childof == "root") {
         childnodename="root"
     } else if (childof == "parent") {
         childnodename="parent"
     } else if (childof != "") {
         childnodename="el" toupper(substr(childof, 1, 1)) substr(childof, 2)
     }
     if (debug > "1") { printf("        /*XMLNOTE childnodename...'%s' */\n", childnodename) }

     makechildnode="N"
     if (substr(childnodename, 1, length(workNodePrefix)) != workNodePrefix) {
         # Child, not elWorkxxx, test if the child node exists...
	 if (childnodename in nodes) {
         } else {
             # no result and childof doesn't exist ... force it to be set...
             makechildnode="Y"
         }
     }
     if (debug > "1") { printf("        /*XMLNOTE makechildnode...'%s' */\n", makechildnode) }

     if ( (typeflag in type_nonvalue_node) && (result == "") ) {
         result=fieldname
         if (debug > "1") { printf("        /*XMLNOTE result..........'%s' - FORCED (empty) */\n", result) }
     }
     if (result != "") {
         result="el" toupper(substr(result, 1, 1)) substr(result, 2)
         if (debug > "1") { printf("        /*XMLNOTE result..........'%s' */\n", result) }
     }

     if ((i=index(item, "[")) > 0) {
         j=index(item, "]")
         indexname=substr(item, i+1, j-i-1)
     } else {
         indexname=""
     }
     if (debug > "1") { printf("        /*XMLNOTE indexname.......'%s' */\n", indexname) }

     if (typeflag in type_macroname_conversion) { 
         macro=type_macroname_conversion[typeflag]
         if (typeflag in macroappend) {
             macroappendvalue=macroappend[typeflag]
         } else {
             macroappendvalue=""
         }
         if (typeflag in macroformat) {
             format=macroformat[typeflag]
         }
     } else if (typeflag in inlinecode_start) {
     } else {
         printf("\n\n ERROR -- type flag '%s' is unknown on following line:\n%5d. %s\n\n", 
                typeflag, 
                lines, 
                $0)
         next
     }

     if ( ( (typeflag == "n") || (typeflag == "nc") ) && (format == "") ) {
         format="d"
         if (debug > "1") printf("      /*XMLNOTE format set to %s */\n", format)
     }
     if ( (typeflag == "f") && (format == "") ) {
         format="f"
         if (debug > "1") printf("      /*XMLNOTE format set to %s */\n", format)
     }
     if (debug > "1") { printf("        /*XMLNOTE macro...........'%s' */\n", macro)
                        printf("        /*XMLNOTE ..appendvalue...'%s' */\n", macroappendvalue)
                        printf("        /*XMLNOTE format..........'%s' */\n", format) }

     # To set the result AND use simplenumeric we can't just use the xmldumpPlugin.c macro...
         # Since this is dependent on the xmldumpPlugin.c macros, we hardcode their names here...
     buftext=""
     if ( (macro=="newxml_simplenumeric") && (result != "") ) {
         if (debug != "") printf("      /*XMLNOTE numeric+result - macroname was %s, set to newxml_smartstring */\n", macro)
         macro="newxml_smartstring"
         buftext=sprintf("safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), \"%%%s\", %s);", 
                         format, itemref)
         format=""
         itemref="buf"
         typeflag="s"
     } else if ( (macro=="newxml_namednumeric") && (result != "") ) {
         if (debug != "") printf("      /*XMLNOTE numeric+result - macroname was %s, set to newxml_smartstring */\n", macro)
         typeflag="SPECIAL1"
     }
     if (debug > "1") { printf("        /*XMLNOTE macro...........'%s' */\n", macro)
                        printf("        /*XMLNOTE itemref.........'%s' */\n", itemref)
                        printf("        /*XMLNOTE buftext.........'%s' */\n", buftext)
                        printf("        /*XMLNOTE typeflag........'%s' */\n", typeflag)
                        printf("        /*XMLNOTE format..........'%s' */\n", format) }

 # Process...

     #  1. Create the child node if necessary...
     if (makechildnode == "Y") {
         if (debug != "") printf("    /*XMLNOTE (auto) generating node %s, child of %s */\n",
                                 childnodename, parentnodename)
         printf("%s/* *****************************************Auto create node** */\n" \
                "%s%s = newxmlna(%s, \"%s\");\n", 
                indent,
                indent, 
                childnodename, 
                parentnodename, 
                childof) >>outputname
         insert_nodes(childnodename, "ChildAutoCreate")
     }

     # 2. Handle inline code...
              #  Just copy all lines until XML*/ found
     if (typeflag == "*") {
         if (debug != "") printf("    /*XMLNOTE Processing (inline) %s, %s */\n", item, description)
         printf("\n%s/* %scopied from %s at line %d */\n", 
                indent, 
                description == "\"\"" ? "" : description " ", 
                ARGV[1],
                lines) >>outputname
         while (getline > 0) {
             if ($1 == "XML*/") { break }
             print indent $0 >>outputname
         }
         printf("%s/* end copy from %s */\n\n", indent, ARGV[1]) >>outputname
         next
     }

     # 2a. Handle XMLINLINE field
     if (typeflag in inlinecode_start) {
         if (debug != "") printf("    /*XMLNOTE Processing (xmlinline) %s, %s */\n", item, description)
         printf("\n%s/*i %sgenerated from %s at line %d */\n", 
                indent, 
                description == "\"\"" ? "" : description " ", 
                ARGV[1],
                lines) >>outputname
         for (i=inlinecode_start[typeflag]; i<inlinecode_end[typeflag]; i++) {
             otext = inlinecode[i]
             j=index(otext, "$")
             while (j>0) {
                 f=substr(otext, j+1, 1)
                 stext = ""
                 if (f == "P") {
                   stext = stripedprefix connect
                 } else if (f == "X") {
                     if (description != "\"\"") {
                         stext = ",\n" indent "/*i*/            \"description\", " description " " 
                     } else {
                         stext = ""
                     }
                 } else if (f == "2") {
                   stext = typeflag
                 } else if (f == "3") {
                   stext = item
                 } else if (f == "4") {
                   stext = childnodename
                 } else if (f == "5") {
                   stext = description
                 }
                 otext = substr(otext, 1, j-1) stext substr(otext, j+2)
                 j=index(otext, "$")
             }
             if (substr(otext, 1, 1) == "#") {
                 print otext >>outputname
             } else {
                 print indent "/*i*/ " otext >>outputname
             }
         }
         next
     }

#
#                                       OUTPUT OUTPUT OUTPUT
#

     # 3. Let's output the code...
     # 3a. SPECIAL1 --
     if (typeflag == "SPECIAL1") {
         # Special case for simplenumeric with result
         if (debug != "") printf("    /*XMLNOTE SPECIAL1 */\n")
         printf("%ssafe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), \"%%%s\", %s);\n",
                        indent, format, itemref) >> outputname
         printf("%s%s = newxml(%s, \"%s\", \n" \
                "%s                \"%s\", buf,\n" \
                "%s                \"description\", %s);\n\n\n",
                indent, result, childnodename, itemname,
                indent, fieldname,
                indent, description) >>outputname
         insert_nodes(result, "special1set")
         next
     }

     # 3z. normal --

     # NULL checks on pointers...
     if ( (typeflag != "e") && (typeprefix ~ /\*/) ) {
         itemrefroot=itemref
         i=index(itemrefroot, "[")
         if (i > 0) {
             itemrefroot=substr(itemrefroot, 1, i-1)
         }
         if (debug > "1") { printf("        /*XMLNOTE itemrefroot.....'%s' */\n", itemrefroot) }

         workprefix=typeprefix
         testprefix=""

         while (workprefix != "") {
             if (debug > "1") { printf("        /*XMLNOTE workprefix......'%s' */\n", workprefix)
                                printf("        /*XMLNOTE testprefix......'%s' */\n", testprefix) }
             printf("%sif (%s%s != NULL) {\n", indent, testprefix, itemrefroot) >>outputname
             workprefix=substr(workprefix, 3)
             testprefix=testprefix "* "
             indent=indent "  "
             if (debug > "1") { printf("        /*XMLNOTE indent..........'%s' */\n", indent) }
         }
     }
   # Normal case, build it up, piece by piece... (Note no \n 's in most pieces)
   #  If there is a sprintf to buf...
     if (buftext != "") {
         printf("%s%s\n", indent, buftext) >>outputname
     }
   #  Start the macro/function... handling it if there is a result
     # indent...
       printf("%s", indent) >>outputname
     # A result?
       if (result != "") {
           printf("%s = ", result) >>outputname
       }
     # Now the function
       if((macro == "newxml_smartstring") && (format == "u")) {
         macro = "newxml_smartstring_u"
         format=""
       }

       printf("%s(%s%s,\n",
              macro, (gdomenode != "" ? gdomenode ", " : ""), childnodename) >>outputname
       printf("%s                        %s%s%s,\n",
              indent, 
              fieldname == "nodename" ? "" : "\"",
              fieldname,
              fieldname == "nodename" ? "" : "\"") >>outputname

     # Skip the "value" piece for non-valued nodes
        if (typeflag in type_nonvalue_node) {
             if (debug != "") { printf("        /*XMLNOTE typeflag '%s' in type_nonvalue_node */\n", typeflag) }
        } else {
            if ( (typeprefix == "") || (typeprefix == "&") ) {
                workprefix = typeprefix
            } else {
                workprefix = substr(typeprefix, 3)
            }
            if (debug > "1") { printf("        /*XMLNOTE workprefix......'%s' */\n", workprefix) }
            printf("%s                        %s%s%s%s,\n",
                   indent, 
                   workprefix,
                   workprefix == "" ? "" : "(",
                   itemref,
                   workprefix == "" ? "" : ")" ) >>outputname
        }

     # Description
       printf("%s                        %s",
              indent, description) >>outputname

     #  Post description parameters (constants, formats, index)
       if (type_macroname_conversion[typeflag] == "newxml_namedstring") {
            printf(",\n%s                        \"%s\"", 
                   indent, itemname) >>outputname
       } else if (type_macroname_conversion[typeflag] == "newxml_namednumeric") {
            printf(",\n%s                        \"%%%s\"",
                   indent, format != "" ? format : "d") >>outputname
            printf(",\n%s                        \"%s\"", 
                   indent, itemname) >>outputname
       } else if (format != "" ) {
            printf(",\n%s                        \"%%%s\"",
                   indent, format) >>outputname
       ##} else if (typeflag in type_appendindex) {
       ##     printf(",\n%s                        %s", 
       ##            indent, type_appendindex[typeflag]) >>outputname
       }

     # Finish it
       printf(");\n\n") >>outputname

   # NULL checks on pointers...
     if ( (typeflag != "e") && (typeprefix ~ /\*/) ) {
         workprefix=typeprefix
         while (workprefix != "") {
             indent=substr(indent, 1, length(indent) - 2)
             workprefix=substr(workprefix, 3)
             printf("%s}\n", indent) >>outputname
         }
     }

     # Remember
     insert_nodes(result, "set")

     next
}

{ next }

END {
    if (outputname != "") { 
        print "" >>outputname
        close(outputname) 
    }
    if (debug != "") {
        printf("/*XMLNOTE recap\n")
        for (i in nodes) {
            printf(" *  %-30s %s\n", i, nodes[i])
        }
        printf(" */\n")

        printf("/*XMLNOTE type_macroname_conversion\n")
        for (i in type_macroname_conversion) {
            printf(" *  %-30s %s\n", i, type_macroname_conversion[i])
        }
        printf(" */\n")

        printf("/*XMLNOTE inline\n")
        for (i in inlinecode_start) {
            printf(" *  %-30s\n", i)
            for (j=inlinecode_start[i]; j<inlinecode_end[i]; j++) {
                printf(" *      %3d %s\n", j-inlinecode_start[i], inlinecode[j])
            }
            printf(" *\n")
        }
        printf(" */\n")
    }
    print "xmldump.awk finished!"
}

