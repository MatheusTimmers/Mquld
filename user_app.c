#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define DEVICE_PATH "/dev/mqueue"
#define MAX_NAME_LEN 30
#define MAX_MESSAGE_LEN 100

// Funções de operação
void register_process(const char *name);
void unregister_process(const char *name);
void send_message(const char *sender_name, const char *target_name, const char *message);
void receive_message(const char *name);

int main() {
    int choice;
    char name[MAX_NAME_LEN];
    char target_name[MAX_NAME_LEN];
    char message[MAX_MESSAGE_LEN];

    printf("Digite o nome do processo: ");
    scanf("%s", name);

    // Registrar o processo
    register_process(name);

    while (1) {
        printf("\nMenu de operações:\n");
        printf("1. Enviar mensagem\n");
        printf("2. Ler mensagem\n");
        printf("3. Desregistrar processo e sair\n");
        printf("Escolha uma opção: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                printf("Nome do processo destinatário: ");
                scanf("%s", target_name);
                printf("Mensagem: ");
                scanf(" %[^\n]", message);
                send_message(name, target_name, message);
                break;
            case 2:
                receive_message(name);
                break;
            case 3:
                unregister_process(name);
                return 0;
            default:
                printf("Opção inválida! Tente novamente.\n");
        }
    }
    return 0;
}

void register_process(const char *name) {
    char command[MAX_NAME_LEN + 5];
    snprintf(command, sizeof(command), "/reg %s", name);

    int fd = open(DEVICE_PATH, O_WRONLY);
    if (fd < 0) {
        perror("Failed to open device file for registration");
        exit(EXIT_FAILURE);
    }

    write(fd, command, strlen(command));
    close(fd);
}

void unregister_process(const char *name) {
    char command[MAX_NAME_LEN + 7];
    snprintf(command, sizeof(command), "/unreg %s", name);

    int fd = open(DEVICE_PATH, O_WRONLY);
    if (fd < 0) {
        perror("Failed to open device file for unregistration");
        exit(EXIT_FAILURE);
    }

    write(fd, command, strlen(command));
    close(fd);
}

void send_message(const char *sender_name, const char *target_name, const char *message) {
    char command[MAX_MESSAGE_LEN + MAX_NAME_LEN + 2];
    snprintf(command, sizeof(command), "/%s %s", target_name, message);

    int fd = open(DEVICE_PATH, O_WRONLY);
    if (fd < 0) {
        perror("Failed to open device file for sending message");
        exit(EXIT_FAILURE);
    }

    write(fd, command, strlen(command));
    close(fd);
    //printf("Mensagem enviada para %s: %s\n", target_name, message);
}

void receive_message(const char *name) {
    char buffer[MAX_MESSAGE_LEN];
    int fd = open(DEVICE_PATH, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open device file for receiving message");
        exit(EXIT_FAILURE);
    }

    ssize_t bytes_read = read(fd, buffer, sizeof(buffer) - 1);
    if (bytes_read < 0) {
        perror("Failed to read message");
    } else if (bytes_read == 0) {
       // printf("Nenhuma mensagem disponível.\n");
    } else {
        buffer[bytes_read] = '\0';  // Certifique-se de terminar a string
        printf("Mensagem recebida: %s\n", buffer);
    }
    close(fd);
}