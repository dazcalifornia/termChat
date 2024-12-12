#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <langinfo.h>
#include <locale.h>
#include <ncurses.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>

#define MAX_CLIENTS 50
#define BUFFER_SIZE 4096
#define USERNAME_SIZE 64
#define PASSKEY_SIZE 64
#define MAX_MESSAGES 1000
#define INPUT_HEIGHT 6       // Increased from 3
#define STATUS_HEIGHT 3      // Height for status bar
#define SERVER_INFO_HEIGHT 3 // Height for server info
#define MAX_MESSAGE_RATE 5   // Maximum messages per second
#define MESSAGE_HISTORY_FILE "chat_history.txt"
#define CONFIG_FILE "chat_config.ini"
#define SSL_CERT_FILE "server.crt"
#define SSL_KEY_FILE "server.key"

// Enhanced client structure with rate limiting
typedef struct {
  int socket;
  SSL *ssl;
  char username[USERNAME_SIZE];
  struct sockaddr_in address;
  time_t last_message_time;
  int message_count;
  time_t rate_limit_start;
  int is_admin;
} client_t;

// Enhanced thread arguments
typedef struct {
  int socket;
  SSL *ssl;
  client_t *clients;
  int *client_count;
  pthread_mutex_t *clients_mutex;
  char *passkey_hash;
  SSL_CTX *ssl_ctx;
} thread_args_t;

// Structure for message history
typedef struct {
  char messages[MAX_MESSAGES][BUFFER_SIZE];
  int count;
  int start;
} message_history_t;

// Configuration structure
typedef struct {
  char host[256];
  int port;
  int max_clients;
  int history_size;
  int rate_limit;
  char ssl_cert[256];
  char ssl_key[256];
  int enable_history;
} config_t;

// Global variables
volatile sig_atomic_t running = 1;
int server_socket = -1;
WINDOW *message_win = NULL;
WINDOW *input_win = NULL;
WINDOW *status_win = NULL;
WINDOW *server_info_win = NULL;
char server_owner[USERNAME_SIZE] = "Unknown";
char server_name[64] = "Chat Server";
message_history_t history = {0};
pthread_mutex_t history_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
int use_tui = 0;
config_t config;

// Function declarations
void handle_signal(int sig);
void *handle_client(void *arg);
void init_windows(void);
void cleanup_windows(void);
void add_message(const char *message);
void calculate_sha256(const char *input, char *output);
int authenticate_client(int client_socket, const char *passkey_hash,
                        char *username);
void format_message(const char *username, const char *message, char *output,
                    size_t output_size);
void broadcast_message(client_t *clients, int *client_count,
                       pthread_mutex_t *clients_mutex, int sender_socket,
                       const char *message, const char *username);

void init_locale_support() {
  if (setlocale(LC_ALL, "") == NULL) {
    fprintf(stderr, "Failed to set locale\n");
    exit(1);
  }

  // Verify UTF-8 support
  char *charset = nl_langinfo(CODESET);
  if (strcmp(charset, "UTF-8") != 0) {
    fprintf(stderr, "Warning: Current locale charset is %s, not UTF-8\n",
            charset);
  }
}

// Enhanced error handling
void handle_error(const char *message) {
  char error_buf[BUFFER_SIZE];
  snprintf(error_buf, sizeof(error_buf), "Error: %s (%s)", message,
           strerror(errno));
  fprintf(stderr, "%s\n", error_buf);
  add_message(error_buf);
}

void play_notification() {
  if (use_tui) {
    beep();  // ncurses beep
    flash(); // visual flash for accessibility
  } else {
    printf("\a"); // ASCII bell
    fflush(stdout);
  }
}

// Configuration file handling
void load_config(const char *filename) {
  FILE *fp = fopen(filename, "r");
  if (!fp) {
    // Set defaults if config file doesn't exist
    strcpy(config.host, "0.0.0.0");
    config.port = 8080;
    config.max_clients = MAX_CLIENTS;
    config.history_size = MAX_MESSAGES;
    config.rate_limit = MAX_MESSAGE_RATE;
    strcpy(config.ssl_cert, SSL_CERT_FILE);
    strcpy(config.ssl_key, SSL_KEY_FILE);
    config.enable_history = 1;
    return;
  }

  char line[256];
  while (fgets(line, sizeof(line), fp)) {
    char key[32], value[224];
    if (sscanf(line, "%31[^=]=%223s", key, value) == 2) {
      if (strcmp(key, "host") == 0)
        strcpy(config.host, value);
      else if (strcmp(key, "port") == 0)
        config.port = atoi(value);
      else if (strcmp(key, "max_clients") == 0)
        config.max_clients = atoi(value);
      else if (strcmp(key, "history_size") == 0)
        config.history_size = atoi(value);
      else if (strcmp(key, "rate_limit") == 0)
        config.rate_limit = atoi(value);
      else if (strcmp(key, "ssl_cert") == 0)
        strcpy(config.ssl_cert, value);
      else if (strcmp(key, "ssl_key") == 0)
        strcpy(config.ssl_key, value);
      else if (strcmp(key, "enable_history") == 0)
        config.enable_history = atoi(value);
    }
  }
  fclose(fp);
}

// Enhanced message history handling
void save_message_to_file(const char *message) {
  if (!config.enable_history)
    return;

  pthread_mutex_lock(&file_mutex);
  FILE *fp = fopen(MESSAGE_HISTORY_FILE, "a");
  if (fp) {
    fprintf(fp, "%s\n", message);
    fflush(fp);
    fclose(fp);
  }
  pthread_mutex_unlock(&file_mutex);
}

void load_message_history() {
  if (!config.enable_history)
    return;

  FILE *fp = fopen(MESSAGE_HISTORY_FILE, "r");
  if (!fp)
    return;

  char line[BUFFER_SIZE];
  pthread_mutex_lock(&history_mutex);
  while (fgets(line, sizeof(line), fp) && history.count < config.history_size) {
    line[strcspn(line, "\n")] = 0;
    strncpy(history.messages[history.count++], line, BUFFER_SIZE - 1);
  }
  pthread_mutex_unlock(&history_mutex);
  fclose(fp);
}

// Enhanced SSL initialization
SSL_CTX *init_ssl_ctx(int is_server) {
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();

  const SSL_METHOD *method =
      is_server ? TLS_server_method() : TLS_client_method();
  SSL_CTX *ctx = SSL_CTX_new(method);

  if (!ctx) {
    ERR_print_errors_fp(stderr);
    return NULL;
  }

  if (is_server) {
    if (SSL_CTX_use_certificate_file(ctx, config.ssl_cert, SSL_FILETYPE_PEM) <=
            0 ||
        SSL_CTX_use_PrivateKey_file(ctx, config.ssl_key, SSL_FILETYPE_PEM) <=
            0) {
      ERR_print_errors_fp(stderr);
      SSL_CTX_free(ctx);
      return NULL;
    }
  }

  return ctx;
}

// Enhanced command handling function
void handle_command(client_t *client, const char *command, client_t *clients,
                    int *client_count, pthread_mutex_t *clients_mutex) {
  char response[BUFFER_SIZE];

  if (strcmp(command, "/users") == 0) {
    // List all connected users
    pthread_mutex_lock(clients_mutex);
    snprintf(response, BUFFER_SIZE, "Connected users (%d/%d):", *client_count,
             MAX_CLIENTS);

    for (int i = 0; i < *client_count; i++) {
      char user_status[128];
      snprintf(user_status, sizeof(user_status), "\n- %s%s",
               clients[i].username, clients[i].is_admin ? " (Admin)" : "");
      strncat(response, user_status, BUFFER_SIZE - strlen(response) - 1);
    }
    pthread_mutex_unlock(clients_mutex);

    // Send the response only to the requesting client
    char formatted[BUFFER_SIZE];
    format_message("System", response, formatted, BUFFER_SIZE);
    send(client->socket, formatted, strlen(formatted), 0);
  } else if (strcmp(command, "/help") == 0) {
    snprintf(response, BUFFER_SIZE,
             "Available commands:\n"
             "/users - List all connected users\n"
             "/msg <username> <message> - Send private message\n"
             "/quit - Exit the chat\n"
             "%s",
             client->is_admin ? "/kick <username> - Kick a user (Admin only)\n"
                              : "");

    char formatted[BUFFER_SIZE];
    format_message("System", response, formatted, BUFFER_SIZE);
    send(client->socket, formatted, strlen(formatted), 0);
  } else if (strncmp(command, "/msg ", 5) == 0) {
    char target[USERNAME_SIZE];
    char message[BUFFER_SIZE];
    if (sscanf(command + 5, "%s %[^\n]", target, message) == 2) {
      pthread_mutex_lock(clients_mutex);
      int found = 0;
      for (int i = 0; i < *client_count; i++) {
        if (strcmp(clients[i].username, target) == 0) {
          char pm_message[BUFFER_SIZE];
          snprintf(pm_message, BUFFER_SIZE, "[Private] %s: %s",
                   client->username, message);
          char formatted[BUFFER_SIZE];
          format_message("Private", pm_message, formatted, BUFFER_SIZE);
          send(clients[i].socket, formatted, strlen(formatted), 0);
          // Also send confirmation to sender
          snprintf(pm_message, BUFFER_SIZE, "Message sent to %s: %s", target,
                   message);
          format_message("Private", pm_message, formatted, BUFFER_SIZE);
          send(client->socket, formatted, strlen(formatted), 0);
          found = 1;
          break;
        }
      }
      pthread_mutex_unlock(clients_mutex);

      if (!found) {
        snprintf(response, BUFFER_SIZE, "User %s not found", target);
        char formatted[BUFFER_SIZE];
        format_message("System", response, formatted, BUFFER_SIZE);
        send(client->socket, formatted, strlen(formatted), 0);
      }
    }
  }
  // Add more commands here
}

// Rate limiting function
int check_rate_limit(client_t *client) {
  time_t current_time = time(NULL);

  if (current_time - client->rate_limit_start >= 1) {
    client->message_count = 0;
    client->rate_limit_start = current_time;
  }

  if (client->message_count >= config.rate_limit) {
    return 0; // Rate limit exceeded
  }

  client->message_count++;
  return 1; // Message allowed
}

// New function to create server info window
void init_server_info_win() {
  int max_y __attribute__((unused)), max_x;
  getmaxyx(stdscr, max_y, max_x);

  server_info_win = newwin(SERVER_INFO_HEIGHT, max_x, 0, 0);
  wattron(server_info_win, COLOR_PAIR(1) | A_BOLD);
  box(server_info_win, 0, 0);
  mvwprintw(server_info_win, 1, 2,
            "Server: %s | Owner: %s | Connected to: %s:%d", server_name,
            server_owner, config.host, config.port);
  wattroff(server_info_win, COLOR_PAIR(1) | A_BOLD);
  wrefresh(server_info_win);
}

// Modified init_windows function
void init_windows() {
  init_locale_support();

  initscr();
  start_color();
  cbreak();
  noecho();
  keypad(stdscr, TRUE);

  if (has_colors()) {
    init_pair(1, COLOR_GREEN, COLOR_BLACK);  // For server info
    init_pair(2, COLOR_CYAN, COLOR_BLACK);   // For usernames
    init_pair(3, COLOR_WHITE, COLOR_BLACK);  // For regular messages
    init_pair(4, COLOR_YELLOW, COLOR_BLACK); // For system messages
  }

  int max_y, max_x;
  getmaxyx(stdscr, max_y, max_x);

  // Create server info window at top
  server_info_win = newwin(SERVER_INFO_HEIGHT, max_x, 0, 0);
  wattron(server_info_win, COLOR_PAIR(1) | A_BOLD);
  box(server_info_win, 0, 0);
  mvwprintw(server_info_win, 1, 2,
            "Server: %s | Owner: %s | Connected to: %s:%d", server_name,
            server_owner, config.host, config.port);
  wattroff(server_info_win, COLOR_PAIR(1) | A_BOLD);

  // Create message window below server info
  message_win = newwin(max_y - INPUT_HEIGHT - SERVER_INFO_HEIGHT, max_x,
                       SERVER_INFO_HEIGHT, 0);
  scrollok(message_win, TRUE);

  // Create input window at bottom
  input_win = newwin(INPUT_HEIGHT, max_x, max_y - INPUT_HEIGHT, 0);
  scrollok(input_win, TRUE);
  box(input_win, 0, 0);
  mvwprintw(input_win, 0, 2, " Message: (Type /help for commands) ");

  // Refresh all windows
  refresh();
  wrefresh(server_info_win);
  wrefresh(message_win);
  wrefresh(input_win);
}

void cleanup_windows() {
  if (use_tui) {
    endwin();
  }
}

// Modified add_message for better UTF-8 handling
void add_message(const char *message) {
  if (!use_tui) {
    printf("%s\n", message);
    fflush(stdout);
    return;
  }

  pthread_mutex_lock(&history_mutex);

  if (history.count < MAX_MESSAGES) {
    strncpy(history.messages[history.count], message, BUFFER_SIZE - 1);
    history.messages[history.count][BUFFER_SIZE - 1] = '\0';
    history.count++;
  } else {
    strncpy(history.messages[history.start], message, BUFFER_SIZE - 1);
    history.messages[history.start][BUFFER_SIZE - 1] = '\0';
    history.start = (history.start + 1) % MAX_MESSAGES;
  }

  werase(message_win);

  // UTF-8 aware message display
  for (int i = 0; i < history.count; i++) {
    int idx = (history.start + i) % MAX_MESSAGES;
    char *msg_copy = strdup(history.messages[idx]);

    // Split message while preserving UTF-8 characters
    char *saveptr;
    char *timestamp = strtok_r(msg_copy, "]", &saveptr);
    char *username = strtok_r(NULL, ":", &saveptr);
    char *content = strtok_r(NULL, "", &saveptr);

    if (timestamp && username && content) {
      wprintw(message_win, "[%s]", timestamp + 1);
      wattron(message_win, COLOR_PAIR(2));
      wprintw(message_win, "%s:", username);
      wattroff(message_win, COLOR_PAIR(2));
      wprintw(message_win, "%s\n", content);
    } else {
      wprintw(message_win, "%s\n", history.messages[idx]);
    }

    free(msg_copy);
  }

  wrefresh(message_win);
  pthread_mutex_unlock(&history_mutex);
}

// SHA-256 implementation
void calculate_sha256(const char *input, char *output) {
  EVP_MD_CTX *context = EVP_MD_CTX_new();
  const EVP_MD *md = EVP_sha256();
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hash_len;

  EVP_DigestInit_ex(context, md, NULL);
  EVP_DigestUpdate(context, input, strlen(input));
  EVP_DigestFinal_ex(context, hash, &hash_len);
  EVP_MD_CTX_free(context);

  for (unsigned int i = 0; i < hash_len; i++) {
    sprintf(output + (i * 2), "%02x", hash[i]);
  }
  output[hash_len * 2] = '\0';
}

// Modified client message handler
void *handle_client_messages(void *arg) {
  thread_args_t *args = (thread_args_t *)arg;
  char buffer[BUFFER_SIZE];

  while (running) {
    int received = recv(args->socket, buffer, BUFFER_SIZE - 1, 0);
    if (received <= 0)
      break;

    buffer[received] = '\0';
    add_message(buffer);
    play_notification(); // Play sound for new message
  }

  free(args);
  return NULL;
}

// Modified start_client function
int start_client(const char *host, int port, const char *username,
                 const char *passkey, int use_ui) {
  init_locale_support();
  struct sockaddr_in server_addr;
  char buffer[BUFFER_SIZE];
  char input_buffer[BUFFER_SIZE];
  char formatted_buffer[BUFFER_SIZE];
  char passkey_hash[EVP_MAX_MD_SIZE * 2 + 1];
  int sock = -1;
  pthread_t receive_thread;

  use_tui = use_ui; // Set the global TUI flag

  if (use_tui) {
    init_windows();
  }
  // Calculate passkey hash
  calculate_sha256(passkey, passkey_hash);

  // Create socket
  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    cleanup_windows();
    perror("Socket creation failed");
    return -1;
  }

  // Configure server address
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  if (inet_pton(AF_INET, host, &server_addr.sin_addr) <= 0) {
    cleanup_windows();
    perror("Invalid address");
    return -1;
  }

  // Connect to server
  if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    cleanup_windows();
    perror("Connection failed");
    return -1;
  }

  // Send authentication
  snprintf(buffer, BUFFER_SIZE, "%s:%s", username, passkey_hash);
  if (send(sock, buffer, strlen(buffer), 0) < 0) {
    cleanup_windows();
    perror("Authentication failed");
    close(sock);
    return -1;
  }

  // Receive authentication response
  int received = recv(sock, buffer, BUFFER_SIZE - 1, 0);
  if (received <= 0) {
    cleanup_windows();
    perror("Authentication response failed");
    close(sock);
    return -1;
  }
  buffer[received] = '\0';

  if (strcmp(buffer, "AUTH_OK") != 0) {
    cleanup_windows();
    printf("Authentication failed: %s\n", buffer);
    close(sock);
    return -1;
  }

  add_message("Connected to chat server. Type '/quit' to exit.");

  // Create receive thread
  thread_args_t *args = malloc(sizeof(thread_args_t));
  args->socket = sock;
  if (pthread_create(&receive_thread, NULL, handle_client_messages, args) !=
      0) {
    cleanup_windows();
    perror("Thread creation failed");
    close(sock);
    free(args);
    return -1;
  }
  pthread_detach(receive_thread);

  // Main input loop
  while (running) {
    if (use_tui) {
      // Clear input line
      wmove(input_win, 1, 1);
      wclrtoeol(input_win);
      box(input_win, 0, 0);
      mvwprintw(input_win, 0, 2, " Message: (Type /help for commands) ");
      wrefresh(input_win);

      // Get input
      echo();
      wmove(input_win, 1, 1);
      memset(input_buffer, 0, BUFFER_SIZE);
      wgetnstr(input_win, input_buffer, BUFFER_SIZE - 1);
      noecho();
    } else {
      if (fgets(input_buffer, BUFFER_SIZE - 1, stdin) == NULL) {
        break;
      }
      input_buffer[strcspn(input_buffer, "\n")] = 0;
    }

    if (strcmp(input_buffer, "/quit") == 0) {
      break;
    }

    if (strlen(input_buffer) > 0) {
      // Handle local commands first
      if (strcmp(input_buffer, "/help") == 0) {
        // Send to server anyway to get server-side commands
        if (send(sock, input_buffer, strlen(input_buffer), 0) < 0) {
          add_message("[Error] Failed to send command");
          break;
        }
        continue;
      }

      // Send all other commands and messages to server
      if (send(sock, input_buffer, strlen(input_buffer), 0) < 0) {
        add_message("[Error] Failed to send message");
        break;
      }

      // Only display local echo for regular messages, not commands
      if (input_buffer[0] != '/') {
        format_message(username, input_buffer, formatted_buffer, BUFFER_SIZE);
        add_message(formatted_buffer);
      }
    }
  }

  cleanup_windows();
  close(sock);
  return 0;
}

void handle_signal(int sig __attribute__((unused))) {
  running = 0;
  if (server_socket != -1) {
    close(server_socket);
  }
}

void *handle_client(void *arg) {
  thread_args_t *args = (thread_args_t *)arg;
  char buffer[BUFFER_SIZE];
  char username[USERNAME_SIZE];
  int client_socket = args->socket;

  // Authenticate client
  if (!authenticate_client(client_socket, args->passkey_hash, username)) {
    close(client_socket);
    free(args);
    return NULL;
  }

  // Add client to list
  pthread_mutex_lock(args->clients_mutex);
  int idx = (*args->client_count)++;
  args->clients[idx].socket = client_socket;
  strncpy(args->clients[idx].username, username, USERNAME_SIZE - 1);
  pthread_mutex_unlock(args->clients_mutex);

  // Announce new user
  char announce[BUFFER_SIZE];
  snprintf(announce, BUFFER_SIZE, "%s joined the chat", username);
  broadcast_message(args->clients, args->client_count, args->clients_mutex, -1,
                    announce, "System");

  // Handle messages
  while (running) {
    int received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
    if (received <= 0)
      break;

    buffer[received] = '\0';
    broadcast_message(args->clients, args->client_count, args->clients_mutex,
                      client_socket, buffer, username);
  }

  // Remove client
  pthread_mutex_lock(args->clients_mutex);
  for (int i = 0; i < *args->client_count; i++) {
    if (args->clients[i].socket == client_socket) {
      for (int j = i; j < *args->client_count - 1; j++) {
        args->clients[j] = args->clients[j + 1];
      }
      (*args->client_count)--;
      break;
    }
  }
  pthread_mutex_unlock(args->clients_mutex);

  // Announce user left
  snprintf(announce, BUFFER_SIZE, "%s left the chat", username);
  broadcast_message(args->clients, args->client_count, args->clients_mutex, -1,
                    announce, "System");

  close(client_socket);
  free(args);
  return NULL;
}

void format_message(const char *username, const char *message, char *output,
                    size_t output_size) {
  time_t now;
  struct tm *timeinfo;
  char timestamp[20];

  time(&now);
  timeinfo = localtime(&now);
  strftime(timestamp, sizeof(timestamp), "%H:%M:%S", timeinfo);

  snprintf(output, output_size, "[%s] %s: %s", timestamp, username, message);
}

// Modified broadcast_message function
void broadcast_message(client_t *clients, int *client_count,
                       pthread_mutex_t *clients_mutex, int sender_socket,
                       const char *message, const char *username) {
  char buffer[BUFFER_SIZE];
  format_message(username, message, buffer, BUFFER_SIZE);

  pthread_mutex_lock(clients_mutex);
  for (int i = 0; i < *client_count; i++) {
    if (clients[i].socket != sender_socket) {
      send(clients[i].socket, buffer, strlen(buffer), 0);
    }
  }
  pthread_mutex_unlock(clients_mutex);
}

int authenticate_client(int client_socket, const char *passkey_hash,
                        char *username) {
  char buffer[BUFFER_SIZE];
  int received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);

  if (received <= 0)
    return 0;
  buffer[received] = '\0';

  char *token = strtok(buffer, ":");
  if (!token)
    return 0;
  strncpy(username, token, USERNAME_SIZE - 1);

  token = strtok(NULL, ":");
  if (!token || strcmp(token, passkey_hash) != 0) {
    send(client_socket, "Invalid passkey", 14, 0);
    return 0;
  }

  send(client_socket, "AUTH_OK", 7, 0);
  return 1;
}

int start_server(const char *host, int port, const char *passkey) {
  struct sockaddr_in server_addr;
  pthread_t thread_id;
  client_t *clients = calloc(MAX_CLIENTS, sizeof(client_t));
  int client_count = 0;
  pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;
  char passkey_hash[EVP_MAX_MD_SIZE * 2 + 1];

  // Calculate passkey hash
  calculate_sha256(passkey, passkey_hash);

  // Set up signal handling
  signal(SIGINT, handle_signal);

  // Create socket
  server_socket = socket(AF_INET, SOCK_STREAM, 0);
  if (server_socket == -1) {
    perror("Socket creation failed");
    return -1;
  }

  // Set socket options
  int opt = 1;
  if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) <
      0) {
    perror("Setsockopt failed");
    return -1;
  }

  // Configure server address
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  if (inet_pton(AF_INET, host, &server_addr.sin_addr) <= 0) {
    perror("Invalid address");
    return -1;
  }

  // Bind socket
  if (bind(server_socket, (struct sockaddr *)&server_addr,
           sizeof(server_addr)) < 0) {
    perror("Bind failed");
    return -1;
  }

  // Listen for connections
  if (listen(server_socket, 5) < 0) {
    perror("Listen failed");
    return -1;
  }

  printf("Chat server started on %s:%d\n", host, port);

  while (running) {
    client_t new_client;
    socklen_t addr_size = sizeof(new_client.address);

    // Accept new connection
    new_client.socket = accept(
        server_socket, (struct sockaddr *)&new_client.address, &addr_size);
    if (new_client.socket < 0) {
      if (running)
        perror("Accept failed");
      continue;
    }

    // Check if maximum clients reached
    if (client_count >= MAX_CLIENTS) {
      printf("Maximum clients reached. Connection rejected.\n");
      close(new_client.socket);
      continue;
    }

    // Allocate thread arguments
    thread_args_t *args = malloc(sizeof(thread_args_t));
    args->socket = new_client.socket;
    args->clients = clients;
    args->client_count = &client_count;
    args->clients_mutex = &clients_mutex;
    args->passkey_hash = passkey_hash;

    // Create new thread for client
    if (pthread_create(&thread_id, NULL, handle_client, args) != 0) {
      perror("Thread creation failed");
      close(new_client.socket);
      free(args);
      continue;
    }
    pthread_detach(thread_id);
  }

  // Cleanup
  free(clients);
  close(server_socket);
  return 0;
}

// Update the server info (call this when information changes)
void update_server_info(const char *new_owner, const char *new_server_name) {
  strncpy(server_owner, new_owner, USERNAME_SIZE - 1);
  strncpy(server_name, new_server_name, sizeof(server_name) - 1);

  if (use_tui && server_info_win) {
    werase(server_info_win);
    box(server_info_win, 0, 0);
    mvwprintw(server_info_win, 1, 2,
              "Server: %s | Owner: %s | Connected to: %s:%d", server_name,
              server_owner, config.host, config.port);
    wrefresh(server_info_win);
  }
}

int main(int argc, char *argv[]) {

  load_config(CONFIG_FILE);
  // Set UTF-8 locale before anything else
  if (setlocale(LC_ALL, "") == NULL) {
    fprintf(stderr, "Failed to set locale. Check your locale settings.\n");
    return 1;
  }

  // Verify UTF-8 support
  char *charset = nl_langinfo(CODESET);
  if (strcmp(charset, "UTF-8") != 0) {
    fprintf(stderr, "Warning: Current locale charset is %s, not UTF-8\n",
            charset);
    fprintf(stderr,
            "Please set your LANG environment variable to a UTF-8 locale\n");
    fprintf(stderr, "For example: export LANG=en_US.UTF-8\n");
    return 1;
  }
  if (argc < 5) {
    printf("Usage:\n");
    printf("Server mode: %s -s <host> <port> <passkey>\n", argv[0]);
    printf("Client mode: %s -c <host> <port> <username> <passkey> [-t]\n",
           argv[0]);
    printf("  -t : Enable TUI mode (optional)\n");
    return 1;
  }

  if (strcmp(argv[1], "-s") == 0) {
    if (argc != 5) {
      printf("Invalid number of arguments for server mode\n");
      return 1;
    }
    return start_server(argv[2], atoi(argv[3]), argv[4]);
  } else if (strcmp(argv[1], "-c") == 0) {
    if (argc < 6 || argc > 7) {
      printf("Invalid number of arguments for client mode\n");
      return 1;
    }
    int use_tui = (argc == 7 && strcmp(argv[6], "-t") == 0);
    return start_client(argv[2], atoi(argv[3]), argv[4], argv[5], use_tui);
  } else {
    printf("Invalid mode. Use -s for server or -c for client\n");
    return 1;
  }
}
