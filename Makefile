CC = gcc
CFLAGS = -Wall -Wextra -I/opt/homebrew/opt/openssl@3/include
LDFLAGS = -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto -lncurses -pthread

chat: chat.c
	$(CC) $(CFLAGS) -o chat chat.c $(LDFLAGS)

clean:
	rm -f chat