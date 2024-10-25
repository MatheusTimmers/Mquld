#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

#define DEVICE_PATH "/dev/mqueue"
#define MAX_NAME_LEN 30
#define MAX_MESSAGE_LEN 100

void register_process(const char *name) {
    char command[MAX_NAME_LEN + 5];
    snprintf(command, sizeof(command), "/reg %s", name);
    
    int fd = open(DEVICE_PATH, O_WRONLY);
    if (fd < 0) {
        perror("Failed to open device file");
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
        perror("Failed to open device file");
        exit(EXIT_FAILURE);
    }

    write(fd, command, strlen(command));
    close(fd);
}

void send_message(const char *sender_name, const char *target_name, int count) {
    char command[MAX_NAME_LEN * 2 + MAX_MESSAGE_LEN + 10];
    snprintf(command, sizeof(command), "/%s ola, %s eu sou %s essa eh a minha %d mensagem para voce", 
    target_name, target_name, sender_name, count);
    
    int fd = open(DEVICE_PATH, O_WRONLY);
    if (fd < 0) {
        perror("Failed to open device file");
        exit(EXIT_FAILURE);
    }

    write(fd, command, strlen(command));
    close(fd);
}

void read_messages(const char *name) {
    int fd = open(DEVICE_PATH, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open device file for reading");
        exit(EXIT_FAILURE);
    }

    char buffer[MAX_MESSAGE_LEN];
    int bytes_read;

    while ((bytes_read = read(fd, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';
        printf("Mensagem recebida por %s: %s\n", name, buffer);
    }

    close(fd);
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Uso: %s <nome> <proc1> <number>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *name = argv[1];
    const char *target1 = argv[2];
    int message_count = atoi(argv[3]);

    // Registrar o processo no módulo
    register_process(name);

    // solução preguiçosa
    sleep(5);

    // Enviar mensagens para os processos alvos
    for (int i = 1; i <= message_count; i++) {
        send_message(name, target1, i);
        printf("Processo %s enviou mensagem %d para %s.\n", name, i, target1);
    }

    // Ler mensagens recebidas após o envio
    printf("Processo %s está lendo mensagens recebidas...\n", name);
    read_messages(name);

    // Desregistrar o processo no módulo
    unregister_process(name);

    return 0;
}