#/* #undef CFG_BIG_ENDIAN */
#
#/* Configuration file directory */
##define CFG_CONFIGFILE_DIR "/usr/share/ntop"
#
/RETSIGTYPE/ { next }
/const/      { next }
/inline/     { next }
/pid_t/      { next }
/size_t/     { next }
/vfork/      { next }
/volatile/   { next }
/PACKAGE_/   { next }
/VERSION/    { next }
/CRAY_STACKSEG_END/ { next }
/ENDIAN/     { next }
/CFG_[A-Z]*_DIR/ { next }
/CFG_NEED_GETDOMAINNAME/ { next }

$2 == "PACKAGE" { next }

$1 == "#define" {
    print $2 " " ($3 == "*/" ? "*" : ($3 == "1" ? "*" : $3))
}

$2 == "#define" {
    print $3 " " ($4 == "*/" ? "*" : ($4 == "1" ? "*" : $4))
}

$1 == "#undef" {
    print $2 " " ($3 == "*/" ? "*" : ($3 == "1" ? "*" : $3))
}

$2 == "#undef" {
    print $3 " " ($4 == "*/" ? "*" : ($4 == "1" ? "*" : $4))
}

