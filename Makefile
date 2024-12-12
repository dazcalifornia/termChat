CC = gcc
CFLAGS = -Wall -Wextra -Werror -O2 -I/opt/homebrew/opt/openssl@3/include
LDFLAGS = -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto -lncurses -pthread
DEBUGFLAGS = -g -DDEBUG

SRCS = chat.c
OBJS = $(SRCS:.c=.o)
TARGET = chat

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

debug: CFLAGS += $(DEBUGFLAGS)
debug: all

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)

install:
	install -m 755 $(TARGET) /usr/local/bin

.PHONY: all debug clean install
