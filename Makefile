# -*- MakeFile -*-

ifeq ($(OS), Windows_NT)
	target = win
	clr = win_clean
endif

all: $(target)

win: main.o trans.o cache.o table.o debug.o
	gcc main.o trans.o cache.o table.o debug.o -o dnsrelay -lws2_32

main.o: main.c cache.h debug.h defs.h table.h trans.h
	gcc -c main.c

cache.o: cache.c cache.h debug.h
	gcc -c cache.c

debug.o: debug.c debug.h
	gcc -c debug.c

table.o: table.c table.h debug.h
	gcc -c table.c

trans.o: trans.c trans.h
	gcc -c trans.c

clean: $(clr)

win_clean:
	del *.o dnsrelay.exe
