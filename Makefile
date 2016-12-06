CFLAGS = -Wall

ifndef NDEBUG
CFLAGS += -O0 -ggdb
STRIP = ls -la
else
CFLAGS += -Os -s -flto -ffunction-sections -fdata-sections -fno-asynchronous-unwind-tables -fomit-frame-pointer -Wl,--gc-sections
STRIP = strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag
endif

all: stegive

test.bin: tweetnacl.c
	./pack.py $+ > $@

.PHONY: test
test: stegive test.bin
	./stegive test.bin tweetnacl.c | md5sum
	md5sum tweetnacl.c

stegive: stegive.o tweetnacl.o main.o
	$(CC) $(CFLAGS) -o $@ $+
	$(STRIP) $@

clean:
	rm -f *.o stegive test.bin