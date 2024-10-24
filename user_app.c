#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define DEVICE_PATH "/dev/mqueue"

void register_process(int fd, const char *process_name) {
    char command[50];
    snprintf(command, sizeof(command), "/reg %s", process_name);

    if (write(fd, command, strlen(command)) < 0) {
        perror("Failed to register the process");
    } else {
        printf("Process %s registered successfully.\n", process_name);
    }
}

void send_message(int fd, const char *process_name, const char *message) {
    char command[256];
    snprintf(command, sizeof(command), "/%s %s", process_name, message);

    if (write(fd, command, strlen(command)) < 0) {
        perror("Failed to send the message");
    } else {
        printf("Message sent to process %s: %s\n", process_name, message);
    }
}

void unregister_process(int fd, const char *process_name) {
    char command[50];
    snprintf(command, sizeof(command), "/unreg %s", process_name);

    if (write(fd, command, strlen(command)) < 0) {
        perror("Failed to unregister the process");
    } else {
        printf("Process %s unregistered successfully.\n", process_name);
    }
}

void read_message(int fd) {
    char buffer[256];
    ssize_t ret;

    ret = read(fd, buffer, sizeof(buffer) - 1);
    if (ret < 0) {
        perror("Failed to read from the device");
    } else {
        buffer[ret] = '\0'; // Garantir que a string tenha null-terminated
        printf("Received message: %s\n", buffer);
    }
}

int main() {
    int fd;
    int choice;
    char process_name[30];
    char message[256];

    // Abrir o dispositivo
    fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        perror("Failed to open the device");
        return -1;
    }

    while (1) {
        printf("\nChoose an operation:\n");
        printf("1. Register process\n");
        printf("2. Send message\n");
        printf("3. Unregister process\n");
        printf("4. Read message\n");
        printf("5. Exit\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                printf("Enter process name: ");
                scanf("%s", process_name);
                register_process(fd, process_name);
                break;

            case 2:
                printf("Enter process name: ");
                scanf("%s", process_name);
                printf("Enter message: ");
                getchar(); // Limpar o buffer
                fgets(message, sizeof(message), stdin);
                message[strcspn(message, "\n")] = '\0'; // Remover newline
                send_message(fd, process_name, message);
                break;

            case 3:
                printf("Enter process name to unregister: ");
                scanf("%s", process_name);
                unregister_process(fd, process_name);
                break;

            case 4:
                read_message(fd);
                break;

            case 5:
                close(fd);
                printf("Exiting...\n");
                return 0;

            default:
                printf("Invalid choice. Please try again.\n");
        }
    }

    return 0;
}

