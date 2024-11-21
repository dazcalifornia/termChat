#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>
#include <signal.h>
#include <openssl/evp.h>
#include <ncurses.h>

#define MAX_CLIENTS 10
#define BUFFER_SIZE 2048
#define USERNAME_SIZE 32
#define PASSKEY_SIZE 64
#define MAX_MESSAGES 100
#define INPUT_HEIGHT 3

// Structure to hold client information
typedef struct {
    int socket;
    char username[USERNAME_SIZE];
    struct sockaddr_in address;
} client_t;

// Structure to hold thread arguments
typedef struct {
    int socket;
    client_t* clients;
    int* client_count;
    pthread_mutex_t* clients_mutex;
    char* passkey_hash;
} thread_args_t;

// Structure for message history
typedef struct {
    char messages[MAX_MESSAGES][BUFFER_SIZE];
    int count;
    int start;
} message_history_t;

// Global variables
volatile sig_atomic_t running = 1;
int server_socket = -1;
WINDOW *message_win = NULL;
WINDOW *input_win = NULL;
message_history_t history = {0};
pthread_mutex_t history_mutex = PTHREAD_MUTEX_INITIALIZER;
int use_tui = 0;

// Function declarations
void handle_signal(int sig);
void* handle_client(void* arg);
void init_windows(void);
void cleanup_windows(void);
void add_message(const char* message);
void calculate_sha256(const char* input, char* output);
int authenticate_client(int client_socket, const char* passkey_hash, char* username);
void format_message(const char* username, const char* message, char* output, size_t output_size);
void broadcast_message(client_t* clients, int* client_count, pthread_mutex_t* clients_mutex,
                      int sender_socket, const char* message, const char* username);

// Initialize TUI windows
void init_windows() {
    initscr();
    start_color();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    
    init_pair(1, COLOR_GREEN, COLOR_BLACK);
    init_pair(2, COLOR_CYAN, COLOR_BLACK);
    init_pair(3, COLOR_WHITE, COLOR_BLACK);
    
    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);
    
    message_win = newwin(max_y - INPUT_HEIGHT, max_x, 0, 0);
    scrollok(message_win, TRUE);
    
    input_win = newwin(INPUT_HEIGHT, max_x, max_y - INPUT_HEIGHT, 0);
    scrollok(input_win, TRUE);
    
    box(input_win, 0, 0);
    
    refresh();
    wrefresh(message_win);
    wrefresh(input_win);
}

void cleanup_windows() {
    if (use_tui) {
        endwin();
    }
}

void add_message(const char* message) {
    if (!use_tui) {
        printf("%s\n", message);
        fflush(stdout);
        return;
    }

    pthread_mutex_lock(&history_mutex);
    
    if (history.count < MAX_MESSAGES) {
        strcpy(history.messages[history.count], message);
        history.count++;
    } else {
        strcpy(history.messages[history.start], message);
        history.start = (history.start + 1) % MAX_MESSAGES;
    }
    
    werase(message_win);
    for (int i = 0; i < history.count; i++) {
        int idx = (history.start + i) % MAX_MESSAGES;
        
        char *timestamp = strtok(strdup(history.messages[idx]), "]");
        char *username = strtok(NULL, ":");
        char *content = strtok(NULL, "");
        
        if (timestamp && username && content) {
            wprintw(message_win, "[%s]", timestamp + 1);
            wattron(message_win, COLOR_PAIR(2));
            wprintw(message_win, "%s:", username);
            wattroff(message_win, COLOR_PAIR(2));
            wprintw(message_win, "%s\n", content);
        } else {
            wprintw(message_win, "%s\n", history.messages[idx]);
        }
    }
    
    wrefresh(message_win);
    pthread_mutex_unlock(&history_mutex);
}

// SHA-256 implementation
void calculate_sha256(const char* input, char* output) {
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_sha256();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    EVP_DigestInit_ex(context, md, NULL);
    EVP_DigestUpdate(context, input, strlen(input));
    EVP_DigestFinal_ex(context, hash, &hash_len);
    EVP_MD_CTX_free(context);

    for(int i = 0; i < hash_len; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[hash_len * 2] = '\0';
}

// Modified client message handler
void* handle_client_messages(void* arg) {
    thread_args_t* args = (thread_args_t*)arg;
    char buffer[BUFFER_SIZE];
    
    while (running) {
        int received = recv(args->socket, buffer, BUFFER_SIZE - 1, 0);
        if (received <= 0) break;
        buffer[received] = '\0';
        add_message(buffer);
    }
    
    free(args);
    return NULL;
}

// Modified start_client function
int start_client(const char* host, int port, const char* username, const char* passkey, int use_ui) {
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    char input_buffer[BUFFER_SIZE];
    char formatted_buffer[BUFFER_SIZE];
    char passkey_hash[EVP_MAX_MD_SIZE * 2 + 1];
    int sock = -1;
    pthread_t receive_thread;
    
    use_tui = use_ui;  // Set the global TUI flag
    
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
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
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
    thread_args_t* args = malloc(sizeof(thread_args_t));
    args->socket = sock;
    if (pthread_create(&receive_thread, NULL, handle_client_messages, args) != 0) {
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
            wrefresh(input_win);
            
            // Get input
            echo();
            wmove(input_win, 1, 1);
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
            // Send message to server
            if (send(sock, input_buffer, strlen(input_buffer), 0) < 0) {
                add_message("Error: Failed to send message");
                break;
            }
            
            // Display own message locally
            format_message(username, input_buffer, formatted_buffer, BUFFER_SIZE);
            add_message(formatted_buffer);
        }
    }
    
    cleanup_windows();
    close(sock);
    return 0;
}

void handle_signal(int sig) {
    running = 0;
    if (server_socket != -1) {
        close(server_socket);
    }
}

void* handle_client(void* arg) {
    thread_args_t* args = (thread_args_t*)arg;
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
    broadcast_message(args->clients, args->client_count, args->clients_mutex,
                     -1, announce, "System");
    
    // Handle messages
    while (running) {
        int received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        if (received <= 0) break;
        
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
    broadcast_message(args->clients, args->client_count, args->clients_mutex,
                     -1, announce, "System");
    
    close(client_socket);
    free(args);
    return NULL;
}

void format_message(const char* username, const char* message, char* output, size_t output_size) {
    time_t now;
    struct tm* timeinfo;
    char timestamp[20];
    
    time(&now);
    timeinfo = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", timeinfo);
    
    snprintf(output, output_size, "[%s] %s: %s", timestamp, username, message);
}


// Modified broadcast_message function
void broadcast_message(client_t* clients, int* client_count, pthread_mutex_t* clients_mutex,
                      int sender_socket, const char* message, const char* username) {
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

int authenticate_client(int client_socket, const char* passkey_hash, char* username) {
    char buffer[BUFFER_SIZE];
    int received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
    
    if (received <= 0) return 0;
    buffer[received] = '\0';
    
    char* token = strtok(buffer, ":");
    if (!token) return 0;
    strncpy(username, token, USERNAME_SIZE - 1);
    
    token = strtok(NULL, ":");
    if (!token || strcmp(token, passkey_hash) != 0) {
        send(client_socket, "Invalid passkey", 14, 0);
        return 0;
    }
    
    send(client_socket, "AUTH_OK", 7, 0);
    return 1;
}

int start_server(const char* host, int port, const char* passkey) {
    struct sockaddr_in server_addr;
    pthread_t thread_id;
    client_t* clients = calloc(MAX_CLIENTS, sizeof(client_t));
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
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
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
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
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
        new_client.socket = accept(server_socket, (struct sockaddr*)&new_client.address, &addr_size);
        if (new_client.socket < 0) {
            if (running) perror("Accept failed");
            continue;
        }
        
        // Check if maximum clients reached
        if (client_count >= MAX_CLIENTS) {
            printf("Maximum clients reached. Connection rejected.\n");
            close(new_client.socket);
            continue;
        }
        
        // Allocate thread arguments
        thread_args_t* args = malloc(sizeof(thread_args_t));
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

int main(int argc, char* argv[]) {
    if (argc < 5) {
        printf("Usage:\n");
        printf("Server mode: %s -s <host> <port> <passkey>\n", argv[0]);
        printf("Client mode: %s -c <host> <port> <username> <passkey> [-t]\n", argv[0]);
        printf("  -t : Enable TUI mode (optional)\n");
        return 1;
    }
    
    if (strcmp(argv[1], "-s") == 0) {
        if (argc != 5) {
            printf("Invalid number of arguments for server mode\n");
            return 1;
        }
        return start_server(argv[2], atoi(argv[3]), argv[4]);
    }
    else if (strcmp(argv[1], "-c") == 0) {
        if (argc < 6 || argc > 7) {
            printf("Invalid number of arguments for client mode\n");
            return 1;
        }
        int use_tui = (argc == 7 && strcmp(argv[6], "-t") == 0);
        return start_client(argv[2], atoi(argv[3]), argv[4], argv[5], use_tui);
    }
    else {
        printf("Invalid mode. Use -s for server or -c for client\n");
        return 1;
    }
}