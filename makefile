SHELL = /bin/bash
CC = gcc
#CFLAGS = -O3
SRC = $(wildcard *.c)
EXE = $(patsubst %.c, %, $(SRC))

all: ${EXE}

%:	%.c
	${CC} ${CFLAGS} $@.c -o $@ -lpcap

clean:
	rm ${EXE}

