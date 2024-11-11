#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUFFER_SIZE 1024

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
        char *echo_arg = NULL;

        // Read each bulk string in the array
        for (int i = 0; i < num_elements; i++) {
          if (buffer[pos] != '$') {
            break;
          }
          pos++; // Skip $

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
          } else if (i == 1) {
            echo_arg = strdup(element);
          }
        }

        if (command) {
          if (strcasecmp(command, "ping") == 0) {
            send(client_fd, "+PONG\r\n", 7, 0);
          } else if (strcasecmp(command, "echo") == 0 && echo_arg) {
            char response[BUFFER_SIZE];
            snprintf(response, BUFFER_SIZE, "$%d\r\n%s\r\n",
                     (int)strlen(echo_arg), echo_arg);
            send(client_fd, response, strlen(response), 0);
          }
        }
      }
    }
  }

  close(client_fd);
}

int main() {
  // Disable output buffering
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  int server_fd, client_addr_len;
  struct sockaddr_in client_addr;

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
