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
/CONST_LLC_/ { next }
/FLAG_/ { next }
/TCPOPT_/ { next }
/ [CT]_/ { next }
/ __/ { next }
/argument/ { next }
/FALSE/ { next }
/TRUE/ { next }
/IN[A-Z0-9]*SZ/ { next }
/FIXEDSZ/ { next }
/WNOHANG/ { next }
/0xffffffff/ { next }
/IPPROTO_/ { next }
/LOG_AUTHPRIV/ { next }
/CONST_URL_PROHIBITED_CHARACTERS/ { next }
/HTML_OPENSSL_URL/ { next }
/DEFAULT_NTOP_MAPPER_URL/ { next }
/SLL_HDR_LEN/ { next }
/SAP_/ { next }
/PROTOTYPES/ { next }
/CONST_TR_/ { next } 
/CONST_FDDIFC_/ { next }
/CONST_[^_]*_TRACE_/ { next }
/ DLT_/ { next }
/atoi\(/ { next }
$2 ~ /\(/ { next } # Skip true macro defines

$2 == "PACKAGE" { next }

/^$/ { next}

{
  i=1
  if ($1 == "/*") {
    i=2
    if ( ($i != "#undef") && ($i != "#define") ) { next }
    shift
  }

  if (substr($i, 1, 1) != "#") { next }
  if (substr($i, 1, 3) == "#if") { next }

  i++

  if (tolower($i) == $i) { next } 

  field=$i

  if ((index(field, "_DEBUG") > 0) && (index(field, "DEFAULT") == 0)) {
     sortname="z" field
  } else {
     sortname=field
  }

  i++

  if ($i == "") {
      tag = "*"
  } else if ($i == "*/") {
      tag = "*"
  } else if ( ($i == "1") && ( (sortname ~ /ENABLE/) ||
                               (sortname ~ /DISABLE/) ||
                               (sortname ~ /SHOW/) ||
                               (sortname ~ /PRINT/) ||
                               (sortname ~ /MAKE/) ||
                               (sortname ~ /HANDLE/) ||
                               (sortname ~ /DEFAULT/) ||
                               (sortname ~ /DEBUG/) ) ) {
      tag = "*"
  } else if ($i == "NULL") {
      tag = "NULL"
  } else if (substr($i,1,1) == "\"") {
      tag = field
  } else {
      tag = "#" field
  }
  print sortname " " tag

}

