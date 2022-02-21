#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#define TYPE_IPV4 "OX0800"
#define TYPE_IPV6 "OX86DD"
#define TYPE_ARP "OX0806"
#define TYPE_CFE "OX8808"
#define TYPE_MAC "OX88E5"
#define TYPE_UNKNOWN "UNKNOWN"

FILE *file;

void dataPack(unsigned char *buffer, int bufferSize)
{
    unsigned char *p = buffer;
    int cont = 0, trama = 0;

    while (bufferSize > 0)
    {
        fprintf(file, "%.2x ", *p);
        p++;
        cont++;
        if (cont > 14)
        {
            trama++;
        }
        bufferSize--;
    }
    fprintf(file, "\n Longitud de la trama: %d\n", cont);
    fprintf(file, "\n Longitud de carga útil (Datos/Relleno): %d / %d\n", trama, cont - trama);
    fprintf(file, "\n---------------------------\n");
}

char *typeOrLen(unsigned char *buffer)
{
    if (buffer[0] == 8 && buffer[1] == 0)
    {
        return TYPE_IPV4;
    }
    else if (buffer[0] == 134 && buffer[1] == 221)
    {
        return TYPE_IPV6;
    }
    else if (buffer[0] == 8 && buffer[1] == 6)
    {
        return TYPE_ARP;
    }
    else if (buffer[0] == 136 && buffer[1] == 8)
    {
        return TYPE_CFE;
    }
    else if (buffer[0] == 136 && buffer[1] == 229)
    {
        return TYPE_MAC;
    }
    else
    {
        return TYPE_UNKNOWN;
    }
}

void fileToHEX(char *msg, unsigned char *buffer, int bufferSize)
{
    fprintf(file, "%s\n", msg);
    while (bufferSize > 0)
    {
        fprintf(file, "%.2x ", *buffer);
        buffer++;
        bufferSize--;
    }
}

void fileProtocolType(unsigned char *buffer)
{
    char *protocolType = typeOrLen(buffer);
    if (strcmp(protocolType, TYPE_IPV4) == 0)
    {
        fprintf(file, "Protocolo: %s (IPv4)\n", protocolType);
    }
    else if (strcmp(protocolType, TYPE_IPV6) == 0)
    {
        fprintf(file, "Protocolo: %s (IPv6)\n", protocolType);
    }
    else if (strcmp(protocolType, TYPE_ARP) == 0)
    {
        fprintf(file, "Protocolo: %s (ARP)\n", protocolType);
    }
    else if (strcmp(protocolType, TYPE_CFE) == 0)
    {
        fprintf(file, "Protocolo: %s (Control de flujo Ethernet)\n", protocolType);
    }
    else if (strcmp(protocolType, TYPE_MAC) == 0)
    {
        fprintf(file, "Protocolo: %s (Seguridad MAC)\n", protocolType);
    }
}

void PrintEthHeader(unsigned char *buffer, int bufferSize)
{
    struct ethhdr *ethHead;
    if (bufferSize > sizeof(struct ethhdr))
    {
        ethHead = (struct ethhdr *)buffer;
        fileToHEX("Dirección MAC destino: ", ethHead->h_dest, 6);
        fprintf(file, "\n");

        fileToHEX("Dirección MAC origen: ", ethHead->h_source, 6);
        fprintf(file, "\n");

        fileProtocolType((void *)&ethHead->h_proto);
        fprintf(file, "\n");
    }
}

void PrintIP(unsigned char *buffer, int bufferSize)
{
    struct ethhdr *ethHead;
    struct iphdr *ipHead;

    ethHead = (struct ethhdr *)buffer;
    if (ntohs(ethHead->h_proto) == ETH_P_ALL)
    {
        if (bufferSize >= (sizeof(struct iphdr) + sizeof(struct ethhdr)))
        {
            ipHead = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        }
    }
}

int main(int argc, char *argv[])
{
    int sock_raw, bufferSize, i = 1;
    int ieeeAn = 0, ethIIAn = 0;
    unsigned char buffer[2048];
    struct sockaddr_ll infoPack, sll;
    struct ifreq ethreq;
    struct ethhdr *ethHead;

    /* Asignar valores pasados por consola */
    char tarjRed[64];
    strcpy(tarjRed, argv[1]);
    int numPaq = atoi(argv[2]);

    /* Iniciar socket */

    sock_raw = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0)
    {
        perror("Error al abrir el socket");
        exit(-1);
    }

    strncpy((char *)ethreq.ifr_name, tarjRed, IFNAMSIZ);

    if ((ioctl(sock_raw, SIOCGIFINDEX, &ethreq)) < 0)
    {
        perror("Error al intentar configurar la NIC especifiada");
        exit(-1);
    }
    printf("NIC: %s\n", ethreq.ifr_name);

    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ethreq.ifr_ifindex;

    /* Comienza lectura de paquetes */

    int infoPackSize = sizeof(infoPack);
    file = fopen("snifferResults.txt", "w+");
    char *kindOfProto;
    int numPaqTot = numPaq;

    while (numPaq > 0)
    {
        if ((bufferSize = recvfrom(sock_raw, buffer, 2048, 0, (struct sockaddr *)&infoPack, (socklen_t *)&infoPackSize)) < 0)
        {
            perror("Error al recibir tramas \n");
            exit(-1);
        }
        ethHead = (struct ethhdr *)buffer;
        printf("Analizando trama recibida #%d...\n", i);
        fprintf(file, "\n\n----- Inicio de Trama %d -------\n\n", i);
        kindOfProto = typeOrLen((void *)&ethHead->h_proto);
        if (strcmp(kindOfProto, TYPE_UNKNOWN) != 0)
        {
            dataPack(buffer, bufferSize);
            PrintEthHeader(buffer, bufferSize);
            ethIIAn++;
        }
        else
        {
            fprintf(file, "\n --------------------------- \nLa trama no puede ser analizada ya que es de tipo IEEE 802.3\n");
            ieeeAn++;
        }

        i++;
        numPaq--;
    }
    fprintf(file, "\n------------------------------ \n");
    fprintf(file, "\nTotal de tramas recibidas: %d\n", numPaqTot);
    fprintf(file, "\nTotal de tramas IEEE 802.3: %d\n", ieeeAn);
    fprintf(file, "\nTotal de tramas Ethernet II: %d\n", ethIIAn);
    fclose(file);

    return 0;
}