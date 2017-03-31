CFLAGS = -Wall

ifndef NDEBUG
CFLAGS += -O0 -ggdb
STRIP = ls -la
else
CFLAGS += -Os -s -flto -ffunction-sections -fdata-sections -fno-asynchronous-unwind-tables -fomit-frame-pointer -Wl,--gc-sections
STRIP = strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag
endif

all: stegive envkey

test.bin: tweetnacl.c
	./pack.py $+ > $@

.PHONY: test
test: stegive envkey test.bin
	./stegive test.bin tweetnacl.c | md5sum
	md5sum tweetnacl.c
	./envkey test | grep EE26B0DD4AF7E749AA1A8EE3C10AE9923F618980772E473F8819A
	./envkey one two | grep 977A5390E5C76416CCB6EC3A58ED36FBFBCA833C01571BB7A3
	./envkey two one | grep 977A5390E5C76416CCB6EC3A58ED36FBFBCA833C01571BB7A3

envkey.o: CFLAGS += -Denvkey_MAIN
envkey.o: envkey.c
envkey.c: envkey.h
envkey: envkey.o tweetnacl.o

stegive: stegive.o tweetnacl.o main.o
	$(CC) $(CFLAGS) -o $@ $+
	$(STRIP) $@

clean:
	rm -f *.o stegive test.bin