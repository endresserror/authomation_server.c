#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <ctype.h>
#include <time.h>
#include <openssl/sha.h>

#define AUTH_PORT 8081
#define BUFFER_SIZE 1024
#define MAX_TOKENS 100
#define TOKEN_LIFETIME 600  // 10分
#define USER_DB "users.txt"

typedef struct {
    char *token;
    time_t timestamp;
} TokenEntry;

TokenEntry valid_tokens[MAX_TOKENS] = {NULL};
pthread_mutex_t token_mutex = PTHREAD_MUTEX_INITIALIZER;

void *handle_auth_connection(void *socket_desc);
int authenticate_user(const char *username, const char *password);
void send_json_response(int client_socket, int success, const char *message);
char *extract_value(const char *buffer, const char *key);
char *url_decode(const char *src);
char *generate_token();
void clean_expired_tokens();
void sha256(const char *str, char outputBuffer[65]);

int main() {
    srand(time(NULL));

    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    pthread_t thread_id;
    int opt = 1;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(AUTH_PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Auth server listening on port %d...\n", AUTH_PORT);

    while (1) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept failed");
            continue;
        }

        int *new_sock = malloc(sizeof(int));
        if (new_sock == NULL) {
            perror("malloc failed");
            close(new_socket);
            continue;
        }

        *new_sock = new_socket;

        if (pthread_create(&thread_id, NULL, handle_auth_connection, (void*) new_sock) < 0) {
            perror("could not create thread");
            free(new_sock);
            close(new_socket);
            continue;
        }
        pthread_detach(thread_id);
    }

    return 0;
}

void *handle_auth_connection(void *socket_desc) {
    int client_socket = *(int*)socket_desc;
    free(socket_desc);

    char buffer[BUFFER_SIZE] = {0};
    ssize_t valread = read(client_socket, buffer, BUFFER_SIZE - 1);
    if (valread <= 0) {
        close(client_socket);
        pthread_exit(NULL);
    }

    buffer[valread] = '\0';

    if (strstr(buffer, "GET /validate") != NULL) {
        clean_expired_tokens();

        char *token_param = strstr(buffer, "token=");
        if (token_param) {
            token_param += 6;
            char *token_end = strchr(token_param, ' ');
            if (token_end) *token_end = '\0';

            int valid = 0;
            pthread_mutex_lock(&token_mutex);
            for (int i = 0; i < MAX_TOKENS; i++) {
                if (valid_tokens[i].token && strcmp(valid_tokens[i].token, token_param) == 0) {
                    valid = 1;
                    break;
                }
            }
            pthread_mutex_unlock(&token_mutex);

            send_json_response(client_socket, valid, valid ? "Token is valid" : "Invalid token");
        }
        close(client_socket);
        pthread_exit(NULL);
    }

    char *body = strstr(buffer, "\r\n\r\n");
    if (!body) {
        send_json_response(client_socket, 0, "Invalid request format");
        close(client_socket);
        pthread_exit(NULL);
    }

    body += 4;

    char *username = extract_value(body, "username");
    char *password = extract_value(body, "password");

    int auth_success = 0;
    if (username && password) {
        auth_success = authenticate_user(username, password);
    }

    if (auth_success) {
        char *token = generate_token();
        char response[BUFFER_SIZE];
        snprintf(response, sizeof(response),
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "\r\n"
                "{"
                "\"success\":true,"
                "\"message\":\"Authentication successful\","
                "\"token\":\"%s\""
                "}",
                token);

        write(client_socket, response, strlen(response));
        free(token);
    } else {
        send_json_response(client_socket, 0, "Authentication failed");
    }

    free(username);
    free(password);
    close(client_socket);
    pthread_exit(NULL);
}

void clean_expired_tokens() {
    time_t now = time(NULL);
    pthread_mutex_lock(&token_mutex);
    for (int i = 0; i < MAX_TOKENS; i++) {
        if (valid_tokens[i].token && (now - valid_tokens[i].timestamp) > TOKEN_LIFETIME) {
            free(valid_tokens[i].token);
            valid_tokens[i].token = NULL;
        }
    }
    pthread_mutex_unlock(&token_mutex);
}

char *generate_token() {
    static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    char *token = malloc(33);
    for (int i = 0; i < 32; i++) {
        token[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }
    token[32] = '\0';

    pthread_mutex_lock(&token_mutex);
    for (int i = 0; i < MAX_TOKENS; i++) {
        if (!valid_tokens[i].token) {
            valid_tokens[i].token = strdup(token);
            valid_tokens[i].timestamp = time(NULL);
            break;
        }
    }
    pthread_mutex_unlock(&token_mutex);

    return token;
}

int authenticate_user(const char *username, const char *password) {
    FILE *file = fopen(USER_DB, "r");
    if (!file) return 0;

    char line[BUFFER_SIZE];
    char stored_username[BUFFER_SIZE];
    char stored_hash[65];
    char password_hash[65];

    sha256(password, password_hash);

    while (fgets(line, sizeof(line), file)) {
        sscanf(line, "%s %s", stored_username, stored_hash);
        if (strcmp(username, stored_username) == 0 && strcmp(password_hash, stored_hash) == 0) {
            fclose(file);
            return 1;
        }
    }
    fclose(file);
    return 0;
}

void sha256(const char *str, char outputBuffer[65]) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)str, strlen(str), hash);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[64] = '\0';
}
