CC = gcc
LD = gcc
PKG_CONFIG = pkg-config
CFLAGS += -Wall -D_FILE_OFFSET_BITS=64
LIBS += -ldvbpsi
RM ?= rm

PREFIX := /usr

all: ts-analyze

ta_SRC := $(wildcard *.c)
ta_OBJ := $(ta_SRC:.c=.o)
ta_HEADERS := $(wildcard *.h)

ts-analyze: $(ta_OBJ)
	$(LD) -o $@ $^ $(LIBS)

%.o: %.c $(ta_HEADERS)
	$(CC) -I. $(CFLAGS) -c -o $@ $<

install: ts-analyze
	install ts-analyze $(PREFIX)/bin

clean:
	$(RM) -f ts-analyze $(ta_OBJ) $(pr_OBJ)

.PHONY: all clean
