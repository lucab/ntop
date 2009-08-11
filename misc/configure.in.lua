dnl>
dnl> Lua - http://www.lua.org
dnl>
LUA_VERSION=lua-5.1.4
if test -f "$LUA_VERSION.tar.gz"; then
   echo "Lua already present on this machine"
else
   wget http://www.lua.org/ftp/$LUA_VERSION.tar.gz
fi

tar xvfz $LUA_VERSION.tar.gz
cat $LUA_VERSION/src/Makefile | sed -e s,'MYCFLAGS=-DLUA_USE_POSIX',' MYCFLAGS="-fPIC -DLUA_USE_POSIX"',g > /tmp/lua.temp
cat /tmp/lua.temp >  $LUA_VERSION/src/Makefile
#rm -f /tmp/lua.temp
cd $LUA_VERSION; make posix; cd ..

LUA_LIB_DIR=$PWD/$LUA_VERSION"/src"
LIBS="-L${LUA_LIB_DIR} -llua ${LIBS} "
INCS="${INCS} -I${LUA_LIB_DIR}"
AC_DEFINE_UNQUOTED(HAVE_LUA, 1, [LUA is supported])

