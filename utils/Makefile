# Standard LIBS
LIBS = -lgdbm

addMacAddress: addMacAddress.o
	$(CC) $(CFLAGS) addMacAddress.o $(LIBS) -o addMacAddress

.c.o:
	@rm -f $@
	$(CC) $(CFLAGS) -c $*.c

clean:
	rm -f *~ #* *.o core addMacAddress