BEGIN {
    echo="off"
    finished="no"
    terms="off"
    blank = 0
}

finished == "yes" {
    next
}

/^AC_INIT/ {
    gsub(/[\[\],]/, " ")
    printf("%s OS Support status extract for version %s\n    Run %s\n\n", $2, $3, strftime())
    printf("%-20s %10s %-10s %-15s\n", "config.guess value", "compiler", "OS name", "Status")
    printf("%-20s %10s %-10s %-15s\n", "------------------", "---------", "---------", "---------------")
}

/^ *\*\-\*\-/ {
    i=index($1, ":")
    if (i > 0) {
        compiler=substr($1, i+1)
        if (length(compiler) > 1) {
            sub(/\*$/, "", compiler)
        }
        $1=substr($1, 1, i-1)
    } else {
        compiler="*"
    }
    flag=substr($1, 5)
    next
}

/STATUS="UNKNOWN"/ { 
    next
}

/DEFINEOS=/ {
    gsub(/[";]/, "")
    i=index($1, "=")
    OS=substr($1, i+1)
    i=index($2, "=")
    STATUS=substr($2, i+1)

    if (STATUS == "SUPPORTED") {
        printf("%-20s %10s %-10s %-15s\n", flag, compiler, OS, STATUS)
    } else if (STATUS == "") {
        printf("%-20s %10s %-10s\n", flag, compiler, OS)
    } else {
        printf("%-20s %10s %-10s %15s\n", flag, compiler, OS, STATUS)
    }
    next
}


/dnl> showoses TERMS/ {
    terms="on"
    next
}

terms == "off" {
    next
}

/dnl> showoses END/ {
    finished="yes"
    terms="off"
    next
}

/^ *[A-Z ]*)/ {
    tag=$1
    sub(/)/, "", tag)
    echo="on"
    print ""
    print "Status of '" tag "' means you are:"
    print ""
    blank = 0
    next
}

/^ *fi$/ {
    echo="on"
    next
}

/^ *if / {
    echo="off"
    next
}

/;;/ {
    echo="off"
    next
}

echo == "off" {
    next
}

/\$/ {
    next
}

/\*\*\*/ {
    next
}

$1 == "echo" {
    gsub(/["\*]/, "")
    gsub(/NOTE:/, "")
    gsub(/ERROR:/, "")
    $1=""
    gsub(/ *$/, "")
    if (length($0) == 0) {
        if (++blank == 1) {
            print ""
        }
        next
    } else {
        blank = 0
    }
    print "    " $0
}

END {
    print ""
    print "Status of blank means that the support level depends"
    print "upon ntop settings and/or other factors."
    print ""
}
