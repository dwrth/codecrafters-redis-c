#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUFFER_SIZE 1024
#define RESP_OK "+OK\r\n"
#define NULL_BULK_STRING "$-1\r\n"
#define PONG_RESPONSE "+PONG\r\n"

typedef struct key_value {
  char key[BUFFER_SIZE];
  char value[BUFFER_SIZE];
} key_value;

static int shm_id;          // Make this global so signal handler can access it
static key_value *kv_store; // Global pointer to shared memory

// Signal handler for graceful shutdown
void cleanup(int signum) {
  printf("\nCleaning up shared memory...\n");

  // Detach and free all key_value structures

  // Detach from shared memory
  if (shmdt(kv_store) == -1) {
    printf("shmdt failed: %s\n", strerror(errno));
  }

  // Remove shared memory segment
  if (shmctl(shm_id, IPC_RMID, NULL) == -1) {
    printf("shmctl failed: %s\n", strerror(errno));
  }

  exit(0);
}

void log_kv_store(char *func_name) {
  printf("Logging kv store in %s\n", func_name);
  for (int i = 0; i < 100; i++) {
    if (kv_store[i].key[0] != '\0') {
      printf("Key: %s, Value: %s\n", kv_store[i].key, kv_store[i].value);
    }
  }
}

void add_to_kv_store(char *key, char *value) {
  for (int i = 0; i < 100; i++) {
    if (kv_store[i].key[0] == '\0' || strcmp(kv_store[i].key, key) == 0) {
      strncpy(kv_store[i].key, key, BUFFER_SIZE - 1);
      kv_store[i].key[BUFFER_SIZE - 1] = '\0';

      strncpy(kv_store[i].value, value, BUFFER_SIZE - 1);
      kv_store[i].value[BUFFER_SIZE - 1] = '\0';

      break;
    }
  }
  printf("added key: %s, value: %s\n", key, value);
}

char *get_from_kv_store(char *key) {
  for (int i = 0; i < 100; i++) {
    if (kv_store[i].key[0] != '\0' && strcmp(kv_store[i].key, key) == 0) {
      printf("Found key: %s, value: %s\n", kv_store[i].key, kv_store[i].value);
      return kv_store[i].value;
    }
  }
  return NULL;
}

// Add helper functions for RESP parsing
char *read_until_crlf(char *buffer, int *pos, int len) {
  static char result[BUFFER_SIZE];
  int i = 0;

  while (*pos < len && i < BUFFER_SIZE - 1) {
    if (buffer[*pos] == '\r' && buffer[*pos + 1] == '\n') {
      result[i] = '\0';
      *pos += 2;
      return result;
    }
    result[i++] = buffer[(*pos)++];
  }
  return NULL;
}

void handle_client(int client_fd) {
  char buffer[BUFFER_SIZE];
  while (1) {
    int bytes_read = read(client_fd, buffer, sizeof(buffer));
    if (bytes_read <= 0)
      break;

    int pos = 0;
    while (pos < bytes_read) {
      if (buffer[pos] == '*') {
        pos++;
        char *num_str = read_until_crlf(buffer, &pos, bytes_read);
        if (!num_str) {
          break;
        }

        int num_elements = atoi(num_str);
        char *command = NULL;
        char *args[num_elements];
        // Read each bulk string in the array
        for (int i = 0; i < num_elements; i++) {
          if (buffer[pos] != '$') {
            break;
          }
          pos++;

          char *len_str = read_until_crlf(buffer, &pos, bytes_read);
          if (!len_str) {
            break;
          }

          char *element = read_until_crlf(buffer, &pos, bytes_read);
          if (!element) {
            break;
          }

          if (i == 0) {
            command = strdup(element);
          } else {
            args[i] = strdup(element);
          }
        }

        if (command == 0) {
          continue;
        }

        if (strcasecmp(command, "ping") == 0) {
          send(client_fd, PONG_RESPONSE, strlen(PONG_RESPONSE), 0);
          continue;
        }

        if (strcasecmp(command, "echo") == 0 && args[1]) {
          char response[BUFFER_SIZE];
          snprintf(response, BUFFER_SIZE, "$%d\r\n%s\r\n", (int)strlen(args[1]),
                   args[1]);
          send(client_fd, response, strlen(response), 0);
          continue;
        }

        if (strcasecmp(command, "set") == 0 && args[1] && args[2]) {
          add_to_kv_store(args[1], args[2]);
          send(client_fd, RESP_OK, strlen(RESP_OK), 0);
          continue;
        }

        if (strcasecmp(command, "get") == 0 && args[1]) {
          char *value = get_from_kv_store(args[1]);
          if (value) {
            char response[BUFFER_SIZE];
            snprintf(response, BUFFER_SIZE, "$%d\r\n%s\r\n", (int)strlen(value),
                     value);
            send(client_fd, response, strlen(response), 0);
          } else {
            send(client_fd, NULL_BULK_STRING, strlen(NULL_BULK_STRING), 0);
          }
          continue;
        }
      }
    }
  }

  close(client_fd);
}

int main() {
  // Register signal handler for Ctrl+C
  signal(SIGINT, cleanup);
  signal(SIGTERM, cleanup);

  // Disable output buffering
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  int server_fd, client_addr_len;
  struct sockaddr_in client_addr;

  // Allocate shared memory for 100 key_value structures
  shm_id = shmget(IPC_PRIVATE, sizeof(key_value) * 100, IPC_CREAT | 0666);
  if (shm_id == -1) {
    perror("shmget failed");
    exit(EXIT_FAILURE);
  }

  kv_store = (key_value *)shmat(shm_id, NULL, 0);
  if (kv_store == (key_value *)-1) {
    perror("shmat failed");
    exit(EXIT_FAILURE);
  }

  // Initialize the shared memory to zero
  memset(kv_store, 0, sizeof(key_value) * 100);

  server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd == -1) {
    printf("Socket creation failed: %s...\n", strerror(errno));
    return 1;
  }

  // Since the tester restarts your program quite often, setting SO_REUSEADDR
  // ensures that we don't run into 'Address already in use' errors
  int reuse = 1;
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) <
      0) {
    printf("SO_REUSEADDR failed: %s \n", strerror(errno));
    return 1;
  }

  struct sockaddr_in serv_addr = {
      .sin_family = AF_INET,
      .sin_port = htons(6379),
      .sin_addr = {htonl(INADDR_ANY)},
  };

  if (bind(server_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != 0) {
    printf("Bind failed: %s \n", strerror(errno));
    return 1;
  }

  int connection_backlog = 5;
  if (listen(server_fd, connection_backlog) != 0) {
    printf("Listen failed: %s \n", strerror(errno));
    return 1;
  }

  printf("Waiting for a client to connect...\n");
  client_addr_len = sizeof(client_addr);

  while (1) {
    int client_fd =
        accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
    printf("Client connected\n");

    pid_t pid = fork();
    if (pid == 0) {
      close(server_fd);
      handle_client(client_fd);

      exit(0);
    } else {
      close(client_fd);
    }
  }

  close(server_fd);

  return 0;
}
