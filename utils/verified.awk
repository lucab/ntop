# Awk script for ./configure -- disassembles a "VERFIED" string
# BMS - 2002/10/21
BEGIN {
    if(ARGC>1) {
      if(ARGV[ARGC-1] ~ /-u/) { 
        unverified="y"
        ARGV[ARGC-1]=""
      }
    }
}

{
    i=index($0, ":")
    if (i>0) {
        vversion=substr($0, 1, i-1)
        $0=substr($0, i+1)
    }
    i=index($0, ":")
    if (i>0) {
        vdate=substr($0, 1, i-1)
        $0=substr($0, i+1)
    }
    i=index($0, ":")
    if (i>0) {
        vby=substr($0, 1, i-1)
        vosversion=substr($0, i+1)
    }
    if(unverified=="y") {
      printf("*     %s\n", vosversion)
    } else {
      printf("*     %-30s ntop %-8s on %s\n", vosversion, vversion, vdate)
#     print "*             by: " vby
    }
}
