CFLAGS=-g
LDFLAGS=

# Naming our phony targets
.PHONY: clean install all p2c mac

# Programs
PROGRAMS=addMacAddress addVlanName inetnum2countryalloc lookuptest p2clib prefixtablegen gdbm_rw
OBJECTS=addMacAddress.o addVlanName.o inetnum2countryalloc.o lookuptest.o p2clib.o prefixtablegen.o 
SOURCES=addMacAddress.c addVlanName.c inetnum2countryalloc.c lookuptest.c p2clib.c prefixtablegen.c 

all: p2c mac vlan gdbm_rw
mac: addMacAddress
vlan: addVlanName
p2c: p2clib inetnum2countryalloc lookuptest prefixtablegen

gdbm_rw: gdbm_rw.c
	$(CC) $(CFLAGS) gdbm_rw.c -lgdbm -o gdbm_rw

addMacAddress: addMacAddress.c
	$(CC) $(CFLAGS) addMacAddress.c -lgdbm -o addMacAddress

addVlanName: addVlanName.c
	$(CC) $(CFLAGS) addVlanName.c -lgdbm -o addVlanName

inetnum2countryalloc: inetnum2countryalloc.c p2clib.h p2clib.o
	$(CC) $(CFLAGS) inetnum2countryalloc.c p2clib.o -o inetnum2countryalloc

lookuptest: lookuptest.c p2clib.h p2clib.o
	$(CC) $(CFLAGS) lookuptest.c p2clib.o -o lookuptest

prefixtablegen: prefixtablegen.c p2clib.h p2clib.o
	$(CC) $(CFLAGS) prefixtablegen.c p2clib.o -lm -o prefixtablegen

p2clib: p2clib.c p2clib.h
	$(CC) $(CFLAGS) -c p2clib.c -o p2clib.o

# Installing the final product
install:
	@echo "Utility programs do not need to be installed!"

.c.o:
	@rm -f $@
	$(CC) $(CFLAGS) -c $*.c

# Removing the executable and the object files
clean:
	@rm -f $(PROGRAMS)
	@rm -f *.o
	@rm -f *~ #* core
	@echo make clean complete

