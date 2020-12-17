SHELL = /bin/bash
CC = gcc
CFLAGS = -g
SRC = $(wildcard *.c)
EXE = $(patsubst %.c, %, $(SRC))

all: ${EXE}

%:	%.c
	${CC} ${CFLAGS} $@.c -o $@ -lpcap

clean:
	rm ${EXE}

