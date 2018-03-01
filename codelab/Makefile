CFLAGS=-Wall -g -Werror -DSOLUTION
PROGS=sink forward swap fe

all: $(PROGS)

sink: sink.o
forward: forward.o
swap: swap.o
fe: fe.o

clean:
	-rm -f *.o $(PROGS)
