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
/STACK_DIRECTION/ { next }
/CRAY_STACKSEG_END/ { next }
/ENDIAN/     { next }
/CFG_[A-Z]*_DIR/ { next }
/CFG_[A-Z]*_ENDIAN/ { next }
/CFG_NEED_GETDOMAINNAME/ { next }
/BITFLAG_/ { next }
/ETHERTYPE_/ { next }
/ICMP_/ { next }
/LLCSAP_/ { next }
/FLAG_/ { next }
/[CT]_/ { next }
/argument/ { next }
/FALSE/ { next }
/TRUE/ { next }
/IN[A-Z0-9]*SZ/ { next }
/FIXEDSZ/ { next }
/WNOHANG/ { next }
/0xffffffff/ { next }
/IPPROTO_/ { next }
/_DEBUG/ { next }
/LOG_/ { next }
/_URL/ { next }
/SLL_HDR_LEN/ { next }
/SAP_/ { next }

$2 == "PACKAGE" { next }

$1 == "#define" {
    print $2 " " (NF == 2 ? "*" : ($3 == "*/" ? "*" : ($3 == "1" ? "*" : (substr($3,1,1) == "\"" ? $2 : "#"$2))))
}

$2 == "#define" {
    print $3 " " (NF == 3 ? "*" : ($4 == "*/" ? "*" : ($4 == "1" ? "*" : (substr($4,1,1) == "\"" ? $3 : "#"$3))))
}

$1 == "#undef" {
    print $2 " " (NF == 2 ? "*" : ($3 == "*/" ? "*" : ($3 == "1" ? "*" : (substr($3,1,1) == "\"" ? $2 : "#"$2))))
}

$2 == "#undef" {
    print $3 " " (NF == 3 ? "*" : ($4 == "*/" ? "*" : ($4 == "1" ? "*" : (substr($4,1,1) == "\"" ? $3 : "#"$3))))
}

