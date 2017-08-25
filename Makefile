CC=gcc
CFLAGS=-Wall -g -Werror -DSOLUTION
PROGS=sink

all: $(PROGS)

sink: sink.o
forward: forward.o
swap: swap.o
fe: fe.o

clean:
	-rm *.o $(PROGS)
