PROGS = mmctl
CLEANFILES = $(PROGS)*.o
CFLAGS = -O2 -pipe
CFLAGS += -Werror -Wall -Wextra
NMSRC := ../netmap
CFLAGS += -I sys -I$(NMSRC)/sys

all: $(PROGS)
mmctl: mmctl.c
	$(CC) $(CFLAGS) -o mmctl mmctl.c
clean:
	-@rm -rf $(CLEANFILES)
