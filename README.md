# Terminal Chat Application

A terminal-based chat application with TUI (Text User Interface) support, UTF-8 character support, and message notifications.

## Features

- Text User Interface (TUI) mode with split screen for messages and input
- Support for UTF-8 characters (multilingual support)
- Sound notifications for new messages
- Secure authentication with passkey
- Color-coded messages
- Message history
- Supports multiple simultaneous connections

## Prerequisites

### macOS

```bash
# Install dependencies using Homebrew
brew install openssl@3 ncurses

# Set locale for UTF-8 support
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

# Enable terminal sound (if needed)
# Go to Terminal > Preferences > Profiles > [Your Profile] > Terminal
# Check "Audible bell"
```

### Linux (Ubuntu/Debian)

```bash
# Install required packages
sudo apt-get update
sudo apt-get install build-essential libssl-dev libncurses5-dev

# Generate required locales
sudo locale-gen en_US.UTF-8 th_TH.UTF-8 ja_JP.UTF-8 ko_KR.UTF-8
sudo update-locale LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8

# Enable terminal bell
xset b on

# For some desktop environments, you might need:
sudo modprobe pcspkr
```

### Linux (Alpine)

```bash
# Install required packages
apk add gcc make musl-dev openssl-dev ncurses-dev linux-headers
apk add musl-locales musl-locales-lang
apk add icu-libs icu-data-full

# Set up locales
cat > /etc/locale.gen << "EOF"
en_US.UTF-8 UTF-8
th_TH.UTF-8 UTF-8
ja_JP.UTF-8 UTF-8
ko_KR.UTF-8 UTF-8
EOF

locale-gen

export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8
```

### Windows (PowerShell)

```powershell
# Set UTF-8 encoding
[System.Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:LANG = "en_US.UTF-8"
```

### Windows (Command Prompt)

```cmd
# Set UTF-8 encoding
chcp 65001
```

## Compilation

### macOS

```bash
# Create Makefile
cat > Makefile << "EOF"
CC = gcc
CFLAGS = -Wall -Wextra -I/opt/homebrew/opt/openssl@3/include
LDFLAGS = -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto -lncurses -pthread

chat: chat.c
	$(CC) $(CFLAGS) -o chat chat.c $(LDFLAGS)

clean:
	rm -f chat
EOF

# Compile
make clean
make
```

### Linux (Ubuntu/Debian/CentOS)

```bash
# Create Makefile
cat > Makefile << "EOF"
CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS = -lssl -lcrypto -lncurses -pthread

chat: chat.c
	$(CC) $(CFLAGS) -o chat chat.c $(LDFLAGS)

clean:
	rm -f chat
EOF

# Compile
make clean
make
```

### Alpine Linux

```bash
# Create Makefile
cat > Makefile << "EOF"
CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS = -lssl -lcrypto -lncurses -pthread -static

chat: chat.c
	$(CC) $(CFLAGS) -o chat chat.c $(LDFLAGS)

clean:
	rm -f chat
EOF

# Compile
make clean
make
```

## Usage

### Starting the Server

```bash
./chat -s <host> <port> <passkey>

# Example:
./chat -s 0.0.0.0 7787 mypassword
```

### Starting the Client

Standard mode:
```bash
./chat -c <host> <port> <username> <passkey>

# Example:
./chat -c 0.0.0.0 7787 john mypassword
```

TUI mode (recommended):
```bash
./chat -c <host> <port> <username> <passkey> -t

# Example:
./chat -c 0.0.0.0 7787 john mypassword -t
```

### Using Different Languages

The chat supports UTF-8 characters, so you can use usernames and messages in various languages:

```bash
# Thai
./chat -c 0.0.0.0 7787 "สมชาย" mypassword -t

# Japanese
./chat -c 0.0.0.0 7787 "田中" mypassword -t

# Korean
./chat -c 0.0.0.0 7787 "홍길동" mypassword -t
```

## Commands

While in chat:
- Type `/quit` to exit the chat
- Press Enter to send a message

## Troubleshooting

1. **Connection Issues**
   ```bash
   # Check if port is in use
   sudo lsof -i :7787
   
   # Kill process using the port if needed
   sudo kill <PID>
   ```

2. **Firewall Issues**
   ```bash
   # Ubuntu/Debian
   sudo ufw allow 7787

   # CentOS/RHEL
   sudo firewall-cmd --zone=public --add-port=7787/tcp --permanent
   sudo firewall-cmd --reload
   ```

3. **Character Display Issues**
   ```bash
   # Verify locale
   locale

   # Set UTF-8 locale if needed
   export LANG=en_US.UTF-8
   export LC_ALL=en_US.UTF-8
   ```

4. **Sound Not Working**
   ```bash
   # Linux
   xset b on
   
   # macOS
   # Check Terminal preferences for "Audible bell"
   ```

## Security Notes

- The passkey is hashed using SHA-256 before transmission
- All connections use TCP sockets
- The server validates all client authentications

## Limitations

- Maximum 10 simultaneous clients (can be changed in code)
- Messages are not encrypted in transit (only passkey is hashed)
- No message persistence (history is lost when client disconnects)
