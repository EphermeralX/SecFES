CC      ?= gcc
CFLAGS  ?= -O2
CFLAGS  += -Wall -Wextra -std=gnu99 -pthread
LDFLAGS ?=
LDLIBS  += -lcrypto -pthread

TARGET = secfes

all: $(TARGET)

$(TARGET): secfes.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
