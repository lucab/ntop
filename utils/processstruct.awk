# ntop xml output generator -- tools

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

# It is designed for the developer of ntop to create a skeleton of 
# certain files used by xmldump.c

#  Usage:   awk -f processstruct.awk xxx.h

# This program processes a c language .h file and attempts to extract
# the structure definitions (typedef struct) so that it can create
# (skeleton) subroutines for insertion into xmldump.c

# It also creates /*XML lines for xmldump.awk to process to create
# the c language code that populates the DOM mode in xmldump.awk

# Understand the limitations - this is not a c parser, it's just dumb
# token matching.  The output is probably pretty good, but it's only
# a start.  If there are inteligent groupings of the fields, that's
# not in the struct, well, it won't figure them out.

# However, if you add a bunch of stuff to a structure, or add a new
# structure, this should save you from manually creating everything.

#  Good Luck!

#     -----Burton

#
# Append - stripping trailing blanks and comments.
#    This is used to build up a single awk string that contains an entire C statement,
#    even if it crosses line boundaries.
#
function specialappend(inputline, append) {
    outputline = inputline " " append
    if ( (i=index(outputline, "/*")) > 0) {
         if ( (j = index(outputline, "*/")) > 0) {
            if (j < i) {
                printf("/*XMLNOTE mis-matched comments, may fail */\n")
            } else {
                outputline=substr(outputline, 1, i-1) " " substr(outputline, j+2)
            }
        }
    }
    gsub(/ +$/, "", outputline)
    return outputline
}

BEGIN {
    programname="processstruct.awk"

    datestamp = strftime("%Y-%m-%dT%H:%M:%S", systime() )

    # export debug=anything to turn on debug
    debug=ENVIRON["XMLDUMPDEBUG"]

    outputfile=ARGV[1]
    if ((i=index(outputfile, ".")) > 0) { outputfile = substr(outputfile, 1, i-1) }
    outputfile=outputfile ".skeleton"

    if (tolower(substr(ARGV[1], 1, 1)) == "globals-structtypes.h") {
        xmlprefix="s"
    } else {
        xmlprefix=tolower(substr(ARGV[1], 1, 1))
    }

    printf("/*XMLNOTE %s %s running */\n", datestamp, programname)
    printf("/*XMLNOTE     Processing %s -> %s */\n", ARGV[1], outputfile)

    printf("/*XMLNOTE %s created on %s from %s */\n\n", outputfile, datestamp, ARGV[1]) >outputfile

    lines=0
    found_typedef="N"
    typedef_name=""
    filename=ARGV[1]

    xmlprefix=tolower(substr(ARGV[1], 1, 1))

#
# This is the translation from c types to /*XML typeflag values
#   e.g. a float is n:f (numeric, format %f)
#
    typewords["float"]="n:f"
    typewords["int"]="n"
    typewords["short"]="n"
    typewords["long"]="n:l"
    typewords["unsigned"]="n:u"
    typewords["u_char"]="n:u"
    typewords["u_int"]="n:u"
    typewords["u_short"]="n:u"
    typewords["char"]="s"
    typewords["volatile"]=""
    typewords["u_int16_t"]="n:u"
    typewords["u_int32_t"]="n:u"
    typewords["u_int"]="n:u"
    typewords["u_long"]="n:lu"

#
# This is used for modifiers (e.g. unsigned int) so that we can merge them.
#
    priority_typewords["unsigned"]="u"

#
# These are used to list know typeflag values, so we don't output them (optionally, debug)
# at the end
#
    codewords["n"]="y"
    codewords["s"]="y"
    codewords["b"]="y"
    codewords["n:u"]="y"
    codewords["n:lu"]="y"
    codewords["n:llu"]="y"

#
# These are hard-coded opaque types which we studiously ignore
#
    ignore_types["pthread_mutex_t"]="yes"
    ignore_types["pthread_cond_t"]="yes"
    ignore_types["gdbm_file"]="yes"
    ignore_types["file"]="yes"
    ignore_types["ssl"]="yes"
    ignore_types["mycode"]="yes"

#
# Current .inc output count
#       Since the name is only valid at the end, we store the generated lines...
#
    ocount=0

    skip="N"
}

#
# Line counter and compress out tabs
#
{
    lines++
    gsub(/\t/, " ")
}

#
# Skip cpp directives... unless we're in the middle, then just echo...
#
substr($1, 1, 1) == "#" { 
    if ( (found_typedef == "Y") && 
         ( ($1 == "#if")        || 
           ($1 == "#ifdef")     || 
           ($1 == "#ifndef")    || 
           ($1 == "#elif")      ||
           ($1 == "#else")      ||
           ($1 == "#endif") ) ) {
        outputecho[ocount] = $0
        ocount++
    }
    next 
}

# Skip directives
$1 == "/*XMLSKIPBEGIN" {
    skip="Y"
    next
}

$1 == "/*XMLSKIPEND" {
    skip="N"
    next
}

skip == "Y" { next }

# If all we have is a comment or a blank line, ignore it
$1 == "/*" && $NF == "*/" { next }
$0 == ""                  { next }
/^[ \t]*$/                { next }

# Comment opening ... skip until the end ... yeah, this is crude...
$1 == "/*" {
     while (getline > 0) {
         lines++
         if (index($0, "*/") > 0) {
             next
         }
     }
     next
}

#
# Stuff we care about begins:
#   typedef struct [optionalcomment] {
#
$1 == "typedef" {
    # Lets skip the simplest ones .... typedef xyz int;
    if (index($0, ";") > 0) { next }
    if ($2 != "struct")     { next }

    found_typedef="Y"

    printf("  /*XMLNOTE Starting typedef at line %d */\n", lines) 
    printf("/*XMLNOTE automatically created from %s starting at line %d */\n", 
           filename, lines) >>outputfile

    next
}

#
# Ends:
#   } name;
#
$1 == "}" {

    found_typedef="N"

    # Create working names... (stripping the ;)
    #    fname is the name, lfname is lower case and pfname is 1st upper, rest lower
    fname=$2
    gsub(/ *;$/, "", fname)
    lfname = tolower(fname)
    pfname = toupper(substr(lfname, 1, 1)) substr(lfname, 2)
    typewords[fname]=lfname

    # Output the header lines
    printf("    /*XMLNOTE Creating %s.inc */\n", lfname)
    printf("/*XMLSECTIONBEGIN xml/%s_%s.inc parent input */\n", xmlprefix, lfname) >>outputfile
    printf("  /*XML e      %-30s %-20s   \"\" */\n", fname, "parent:Work") >>outputfile

    # Output the stored lines
    for (i=0; i<ocount; i++) {
        if (i in outputecho) {
            printf("%s\n", outputecho[i]) >>outputfile
            delete outputecho[i]
            continue
        }
        otype=tolower(outputtype[i])
        gsub(/\*/, "", otype)
        if (i in outputindex) {
            printf("  /*XMLFOR i 0 %s */\n", outputindex[i]) >>outputfile
            indent="    "
        } else {
            indent=""
        }
        if (otype != outputfield[i]) {
            printf("%s  /*XML%s %-6s %-30s %-20s   \"\" */\n", 
                indent,
                otype in ignore_types ? "NOTE - IGNORE " : "",
                otype,
                outputfield[i] (i in outputindex ? "[i]" : ""),
                "Work") >>outputfile
        }
        if (i in outputindex) {
            printf("  /*XMLROF */\n") >>outputfile
            delete outputindex[i]
        }
        delete outputfield[i]
    }
    printf("/*XMLSECTIONEND */\n\n\n") >>outputfile

    printf("/* ********************************** */\n") >>outputfile
    printf("/* *Generated skeleton for xmldump.c* */\n") >>outputfile
    printf("/* * created from %-17s * */\n", filename) >>outputfile
    printf("/* *      at line %4d              * */\n", lines) >>outputfile
    printf("/* *      at %-22s * */\n", datestamp) >>outputfile
    printf("/* ********************************** */\n\n") >>outputfile
    printf("GdomeElement * newxml_%s(GdomeElement * parent,\n", lfname) >>outputfile
    printf("                       char * nodename,\n") >>outputfile
    printf("                       %s * input,\n", fname) >>outputfile
    printf("                       char * description);\n\n") >>outputfile
    printf("GdomeElement * newxml_%s(GdomeElement * parent,\n", lfname) >>outputfile
    printf("                       char * nodename,\n") >>outputfile
    printf("                       %s * input,\n", fname) >>outputfile
    printf("                       char * description) {\n\n") >>outputfile
    printf("    GdomeElement *elWork;\n") >>outputfile
    printf("    GdomeException exc;\n\n") >>outputfile
    printf("#if (XMLDUMP_DEBUG >= 3)\n") >>outputfile
    printf("        traceEvent(CONST_TRACE_INFO, \"XMLDUMP_DEBUG: Starting newxml_%s\\n\");\n", lfname) >>outputfile
    printf("#endif\n\n") >>outputfile
    printf("    /* Insert the generated block of code */\n") >>outputfile
    printf("        #include \"xml/%s_%s.inc\"\n\n", xmlprefix, lfname) >>outputfile
    printf("#if (XMLDUMP_DEBUG >= 3)\n") >>outputfile
    printf("        traceEvent(CONST_TRACE_INFO, \"XMLDUMP_DEBUG: Ending newxml_%s\\n\");\n", lfname) >>outputfile
    printf("#endif\n\n") >>outputfile
    printf("    return elWork;\n") >>outputfile
    printf("}\n\n") >>outputfile
    printf("/* ********************************** */\n") >>outputfile
    printf("/* ********************************** */\n\n") >>outputfile

    # Store the name of the type for later, reset the counter and continue on...
    typelist[lfname]="y"
    ocount=0
    next
}

#
# If we are NOT in the middle of a typedef, then we skip the line...
#
found_typedef == "N" { next }

#
# Otherwise, it's a definition in our struct and we process it...
#
{
    # Process a line...
    #    First, read up to the ; dropping comments

    inputline=""
    inputline = specialappend(inputline, $0)
    gsub(/ +$/, "", inputline)
    while (substr(inputline, length(inputline), 1) != ";") {
        if (getline > 0) {
            lines++
            inputline = specialappend(inputline, $0)
        } else if (substr($1, 1, 1) == "#") {
            continue
        } else {
            printf("/*XMLNOTE no closing ; - assuming, may fail '%s' */\n", inputline)
            inputline=inputline ";"
            break
        }
        gsub(/ +$/, "", inputline)
    }
    while ( (i=index(inputline, "/*")) > 0) {
        j = index(inputline, "*/")
        if (j < i) {
            printf("/*XMLNOTE mis-matched comments, may fail */\n")
            break
        }
        inputline=substr(inputline, 1, i-1) " " substr(inputline, j+2)
    }
    gsub(/ *; *$/, "", inputline)
    if (debug != "") printf("DEBUG: inputline='%s', NF=%d\n", inputline, NF)

    # This gives us an entire C declaration statement.  We'll set $0 to it so we can
    #  use the automatic split and $n variables.
    $0=inputline

    # Process the first field(s) to grab the type.
    #  typetype: We look up the type in the table above until we find the 
    #            first conversion to /*XML typeflag
    #  prioritytypetype is the "u" suffix if needed, again from table above.
    #   This allows us to convert "unsigned int" to n:u while "int" is just "n"
    #  ActualTypeName is just a concat of the words (unsigned long long -> unsignedlonglong)
    #      Used below to see if this is a char xx[n] that we should treat as a string.
    ActualTypeName=""
    typetype=""
    prioritytypetype=""
    for (i=1; i<=NF; i++) {
      typeword=$i
      gsub(/\*$/, "", typeword)
      if (typeword == "struct") { 
          ActualTypeName=ActualTypeName $i
          continue
      } else if (typeword in typewords) {
          ActualTypeName=ActualTypeName $i
          if ( (typetype == "") && (typeword in typewords) && (typewords[typeword] != "") ) {
              typetype = typewords[typeword]
          }
          if ( (prioritytypetype == "") && (typeword in prioritytypewords) ) {
              prioritytypetype = prioritytypewords[typeword]
          }
      } else {
          # Not a type word? Must be the field... stop mucking with types.
          break
      }
    }
    if (typetype == "" ) { typetype = $i }
    if (prioritytypetype != "") { 
        if (index(typetype, ":") == 0) { typetype = typetype ":" }
        typetype = typetype prioritytypetype
    }
    if (debug != "") printf("DEBUG: typetype='%s'\n", typetype)

    # Process the remaining field(s) as variables of the associated type...
    if (debug != "") printf("DEBUG: i=%d, NF=%d\n", i, NF)
    for (; i<=NF; i++) {
        if (debug != "") printf("DEBUG: processing field '%s'\n", $i)
        # Convert **x to x[] 
        if (substr($i, 1, 2) == "**") { 
            $i = substr($i, 3) "[?]" 
            ActualTypeName="forcedarray"
        }
        # If it's got an index value, we need to know for the XMLFOR later on...
        j=index($i, "[")
        if (j>0) {
            field=substr($i, 1, j-1)
            findex=substr($i, j+1)
            gsub(/\]/, "", findex)
        } else {
            field=$i
            findex=""
        }
        # Strip off bit masks, leading *'s, trailing commas
        gsub(/^:[0-9]*/, "", field)
        gsub(/^\*+/, "", field)
        gsub(/\*+$/, "", field)
        gsub(/,$/, "", field)
        if (debug != "") printf("DEBUG: Field %s, type %s\n", field, typetype)

        if (tolower(field) in ignore_types) {
        } else if (field != "") {
            # Store the output data for when we find the }
            outputtype[ocount] = typetype
            outputfield[ocount]= field
            if (findex != "") { 
                if (ActualTypeName ~ /char/) {
                    # char xxx[size]  -- treat as string
                } else {
                    outputindex[ocount] = findex 
                }
            }
            ocount++
        }
    }
    next
}

END {
    datestamp = strftime("%Y-%m-%dT%H:%M:%S", systime() )
##    # Note we explicitly APPEND to the list, in case we have multiple files to process...
##    print "# processstruct.list created " datestamp >>"processstruct.list"
##    print "#    by processstruct.awk "              >>"processstruct.list"
##    print "#    from " ARGV[1]                      >>"processstruct.list"
##    print "#"                                       >>"processstruct.list"

    # Output a list of all the unknown types we've found for xmldump.awk
##    for (i in typelist) {
##        if (i in typewords) {
##            printf("# typewords   %s\n", i) >>"processstruct.list"
##        } else if (i in codewords) {
##            printf("# codewords   %s\n", i) >>"processstruct.list"
##        } else {
##            printf("struct        %s\n", i) >>"processstruct.list"
##        }
##    }
    printf("\n\n/*XMLNOTE %s %s finished */\n\n\n", datestamp, programname)
}
