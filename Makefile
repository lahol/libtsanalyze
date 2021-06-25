CC = gcc
LD = gcc
PKG_CONFIG = pkg-config
CFLAGS += -Wall -D_FILE_OFFSET_BITS=64
LIBS += -ldvbpsi
RM ?= rm

PREFIX := /usr

all: ts-analyze libtsanalyze.so.1.0

ta_SRC := $(filter-out main.c, $(wildcard *.c))
ta_OBJ := $(ta_SRC:.c=.o)
ta_HEADERS := $(wildcard *.h)

libtsanalyze.so.1.0: $(ta_OBJ)
	$(CC) -shared -Wl,-soname,libtsanalyze.so.1 -o $@ $^ $(LIBS)
	ln -sf libtsanalyze.so.1.0 libtsanalyze.so.1
	ln -sf libtsanalyze.so.1 libtsanalyze.so


ts-analyze: main.c libtsanalyze.so.1.0
	$(CC) $(CFLAGS) -L. -o ts-analyze main.c -ltsanalyze $(LIBS)

%.o: %.c $(ta_HEADERS)
	$(CC) -I. $(CFLAGS) -fPIC -c -o $@ $<

install: ts-analyze
	install libtsanalyze.so.1.0 $(PREFIX)/lib/
	ln -sf $(PREFIX)/lib/libtsanalyze.so.1.0 $(PREFIX)/lib/libtsanalyze.so.1
	ln -sf $(PREFIX)/lib/libtsanalyze.so.1 $(PREFIX)/lib/libtsanalyze.so
	cp ts-analyzer.h pidinfo.h $(PREFIX)/include
	install ts-analyze $(PREFIX)/bin

clean:
	$(RM) libtsanalyze.so* ts-analyze $(ta_OBJ) $(pr_OBJ)

.PHONY: all clean install
