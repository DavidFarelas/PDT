#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_NUMS 4
#define PORT 8080

int handle_operation(int[]);

int main()
{
    int socket_desc, client_sock, c, read_size;
    struct sockaddr_in server, client;
    int numbers[MAX_NUMS], i;
    int response;

    /* Creación del socket */
    socket_desc = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_desc == -1)
    {
        perror("No se pudo crear el socket");
        exit(-1);
    }
    puts("Socket creado");

    /* Preparación de la estructura sockaddr_in */
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(PORT);

    /* Enlazando el socket */
    if (bind(socket_desc, (struct sockaddr *)&server, sizeof(server)) < 0)
    {
        perror("Ocurrió un error al enlazar el socket");
        exit(-1);
    }
    puts("Enlace creado");

    /* Socket escuchando */
    listen(socket_desc, 3);

    printf("Esperando por conexiones entrantes a través del puerto %d... \n", PORT);
    c = sizeof(struct sockaddr_in);

    /* Aceptando conexiones de clientes entrantes */
    client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t *)&c);

    if (client_sock < 0)
    {
        perror("Ocurrió un error al aceptar conexiones");
        exit(-1);
    }

    puts("Conexión aceptada");

    /* Recibiendo información desde el cliente */
    while ((read_size = recv(client_sock, &numbers, MAX_NUMS * sizeof(int), 0)) > 0)
    {
        /* Operación con la información recibida */
        response = handle_operation(numbers);

        //sleep(1);

        write(client_sock, &response, sizeof(int));
    }

    if (read_size == 0)
    {
        puts("Se desconectó el cliente");
    }
    else if (read_size == -1)
    {
        perror("Ocurrió un error al recibir información");
        exit(-1);
    }

    return 0;
}

/* Función para realizar la operación */

int handle_operation(int list[])
{
    int response;
    response = ((list[0] + list[1]) * list[2]) - list[3];
    return response;
}