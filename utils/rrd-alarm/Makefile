#
# Configure the BASE variable before compiling the tool
#
BASE=/usr/local/rrdtool/


INCLUDE=-I$(BASE)
LIBS=-L$(BASE).libs -lrrd
CFLAGS=-g -Wall -pedantic -I$(BASE) -I$(BASE) -pipe
CC=gcc

TARGET=rrd_alarm
$(TARGET): $(TARGET).c Makefile
	   $(CC) $(CFLAGS) $(INCLUDE) $(TARGET).c -o $(TARGET) $(LIBS)

clean:
	@/bin/rm -rf *~ $(TARGET) *.png *cache
