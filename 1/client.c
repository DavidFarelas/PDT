#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_NUMS 4
#define IP_ADD "127.0.0.1"
#define PORT 8080

int main()
{
    int numbers[MAX_NUMS], sock, response = 0;
    struct sockaddr_in server;

    /* Creación del socket */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1)
    {
        perror("No se pudo crear el socket");
        exit(-1);
    }
    puts("Socket creado");

    server.sin_addr.s_addr = inet_addr(IP_ADD);
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);

    /* Conexión al servidor */
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0)
    {
        perror("Falló la conexión al servidor");
        exit(-1);
    }

    printf("Conectado al puerto %d \n", PORT);

    while (response < 501)
    {
        /* Lectura de los 4 dígitos */
        puts("Digite 4 números separados por espacios: ");
        scanf("%d %d %d %d", &numbers[0], &numbers[1], &numbers[2], &numbers[3]);

        /* Envío de los dígitos al servidor */
        if (send(sock, &numbers, MAX_NUMS * sizeof(int), 0) < 0)
        {
            perror("Falló el envío de datos al servidor");
            exit(-1);
        }

        /* Captura de la respuesta del servidor */
        if (recv(sock, &response, sizeof(int), 0) < 0)
        {
            perror("Error al recibir información del servidor");
            exit(-1);
        }

        /* Respuesta al usuario */

        if (response < 501)
        {
            puts("\nEl resultado deberá ser mayor a 500\n");
        }
        else
        {
            printf("\nEl resultado de la operación es: %d \n", response);
        }
    }
    /* Se cierra el socket */
    close(sock);
    return 0;
}