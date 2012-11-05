CC?=gcc
CFLAGS?= -O3 -s
CFLAGS+= -DNDEBUG
CFLAGS+= -I/usr/local/include
LDFLAGS+= -larchive -lsqlite3 -L/usr/local/lib
#CFLAGS=-W -Wall -g -O0 -I/usr/local/include -pg

UNAME := $(shell uname)

ifeq ($(UNAME), Linux)
LDFLAGS+= -lrt -lresolv
endif

DESTDIR?=/netup/utm5/

all: ya_get_nf_direct

clean:
	rm -f *.o ya_get_nf_direct

filter.yy.c: filter.l
	flex -i -B -ofilter.yy.c filter.l

ya_get_nf_direct: ya_get_nf_direct.c ya_get_nf_direct.h filter.yy.c filter.l sqlite.c
	$(CC) $(CFLAGS) \
	sqlite.c \
	ya_get_nf_direct.c \
	filter.yy.c \
	-o ya_get_nf_direct $(LDFLAGS)

install:
	mkdir -p ${DESTDIR}/bin 2> /dev/null
	cp -p ya_get_nf_direct ${DESTDIR}/bin
