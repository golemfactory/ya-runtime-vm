CC := musl-gcc

CFLAGS := -std=c11 -O2 -Wall -Werror -fPIE -pie -I../include/

ifneq ($(DEBUG), "")
CFLAGS += -DNDEBUG
endif

.DEFAULT_GOAL = all
.PHONY: all
all: init

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $^

init: init.o communication.o
	$(CC) $(CFLAGS) -static -o $@ $^
	@# default musl libs on some distros have debug symbols, lets strip them (and everythig else)
	strip $@

.PHONY: clean
clean:
	$(RM) init *.o
