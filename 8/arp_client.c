/*
    gcc -pthread -o arp arp_client.c
    sudo ./arp <#IP's a analizar> <Nombre de la tarjeta de red>
*/

#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <string.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <unistd.h>
#include <stdlib.h>
#include <net/if_arp.h>
#include <pthread.h>
#include <arpa/inet.h>

char dev[16]; 

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
struct in_data{
    unsigned char ip_dest[16];
    unsigned char device[IFNAMSIZ];
};

struct  msgARP{
    unsigned char destinoEthernet[6]; //Dirección de difusión 0xF
    unsigned char origenEthernet[6]; //Dirección MAC del transmiso
    unsigned short tipoEthernet; //Tipo de mensaje en la trama Etherne
    unsigned short tipoHardware; //Tipo de hw  para difundir  mensaje ARP 
    unsigned short tipoProtocolo; //Tipo de protocolo de red utilizado para difundir el mensaje ARP (IP)
    unsigned char longitudHardware; //Tamaño de direcciones de hw (6bytes
    unsigned char longitudProtocolo; //Tamaño de direcciones del protocolo (4bytes)
    unsigned short tipoMensaje; // Solicitud o respuest
    unsigned char origenMAC[6]; //Dirección MAC del transmiso
    unsigned char origenIP[4]; //Dirección IP del transmiso
    unsigned char destinoMAC[6]; //Dirección MAC del receptor (dirección solicitada
    unsigned char destinoIP[4]; //Dirección IP del receptor (dato de entrada
};
struct arp_tbl{
    unsigned char ip_src[16];
    unsigned char ip_dst[16];
    unsigned char MAC_src[18];
    unsigned char MAC_dst[18];
};
void *ARP_request(void *ptr);

int main(int argc, char *argv[]){
    if(argv[1]==NULL|argv[2]==NULL){
        printf("ERROR: Ejecutar con argumentos:\n");
        printf("%s <#Numero de IPs a resolver> <tarjeta de red>\n", argv[0]);
        exit(-1);
    }
    int n = atol(argv[1]);
    strcpy(dev, argv[2]);
    pthread_t tid[n];
    for (int i = 0; i < n; ++i){
        char *ip_dest = malloc(16);
        bzero(ip_dest, 16);
        pthread_mutex_lock(&mutex);
        printf("\nIngresa la dirección de destino %d: ", i+1);
        scanf("%s", ip_dest);
        pthread_mutex_unlock(&mutex);
        pthread_create(&tid[i], NULL, ARP_request, ip_dest);
    }
    for(int i = 0; i < n; ++i){
        struct arp_tbl *rply =  malloc(sizeof(struct arp_tbl)); 
        pthread_join(tid[i],(void **)&rply);
        // printf("---Resultados %d \n",i+1);
        // printf("IP fuente: %s\t MAC: %s \n",rply->ip_src, rply->MAC_src);
        // printf("IP destino: %s\t MAC: %s \n",rply->ip_dst, rply->MAC_dst);
        free(rply);
    }
    return 0;
}

void *ARP_request(void *arg){
    char *ip_dst = (char *)arg;
    char *ip_src = malloc(16);
    uint8_t mac_addr[6];
    char mac_src[18];
    /*
        Abrir un socket de capa 2.
    */
    int sock_errno(void), sock;
    if((sock = socket(PF_PACKET, SOCK_PACKET, htons(ETH_P_ARP))) < 0){
        printf("ERROR: No se pudo abrir el socket, %d\n", sock);
        exit(1);
    }
    /*
        Configurar socket para difusion.
    */
    int optval;
    setsockopt(sock,SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval));
    /*
        Configurar NIC modo promiscuo:
    */
    struct sockaddr_in *addr; 
    struct ifreq eth;
    strncpy(eth.ifr_name, dev, IFNAMSIZ);
    ioctl(sock, SIOCGIFFLAGS, &eth);
    // Operacion or a nivel bit para configurar modo promiscuo
    eth.ifr_flags |= IFF_PROMISC;
    if (ioctl(sock, SIOCSIFFLAGS, &eth) == -1) {
        perror("Error: No se pudo establecer la configuracion en modo Promiscuo");
        exit(1);
    }

    // Obtener direccion ip.
    if (ioctl(sock, SIOCGIFADDR, &eth) != 0){
        perror("Error: No se puede obtener la direccion ip");
        exit(1);
    }
    addr = (struct sockaddr_in *)&(eth.ifr_addr);
    ip_src = inet_ntoa(addr->sin_addr);
    // Obtener direccion MAC.
    if (ioctl(sock, SIOCGIFHWADDR, &eth) != 0) {
        perror("Error: No se puede obtener la direccion MAC");
        exit(1);
    }
    memcpy(mac_addr, eth.ifr_hwaddr.sa_data, sizeof(mac_addr));
    sprintf(mac_src,"%02X:%02X:%02X:%02X:%02X:%02X",
        mac_addr[0],mac_addr[1],mac_addr[2],
        mac_addr[3],mac_addr[4],mac_addr[5]);
    /*
        Creacion del Packete ARP request
    */
    struct msgARP msgARP;

    for (int i=0;i<6;i++) msgARP.destinoEthernet[i] = 0xFF;
    for (int i=0;i<6;i++) msgARP.origenEthernet[i] = mac_addr[i];
    msgARP.tipoEthernet = htons(ETH_P_ARP);
    msgARP.tipoHardware = htons(ARPHRD_ETHER);
    msgARP.tipoProtocolo = htons(ETH_P_IP);
    msgARP.longitudHardware = 6;
    msgARP.longitudProtocolo = 4;
    msgARP.tipoMensaje = htons(ARPOP_REQUEST);
    for (int i=0;i<6; i++) msgARP.origenMAC[i] = mac_addr[i];
    char ip_byte[4];
    int j = 0, n_byte = 0;
    for (int i=0;i<=strlen(ip_src);i++){
        if (ip_src[i] == '.' || ip_src[i]=='\0'){
            bzero(ip_byte,3);
            strncpy(ip_byte, &ip_src[i-j],j);
            msgARP.origenIP[n_byte] = (unsigned char) atoi(ip_byte);
            j=0;
            n_byte++;   
        }else
            j++;
    }
    for (int i=0;i<6; i++) msgARP.destinoMAC[i] = 0x00;
    j=0;n_byte=0;
    for (int i=0;i<=strlen(ip_dst);i++){
        if (ip_dst[i] == '.' || ip_dst[i]=='\0'){
            bzero(ip_byte,3);
            strncpy(ip_byte, &ip_dst[i-j],j);
            msgARP.destinoIP[n_byte] = (unsigned char) atoi(ip_byte);
            j=0;
            n_byte++;   
        }else
            j++;
    }
    /*
        Definir interfaz de red para eviar arp request
    */
    struct sockaddr add;
    strncpy(add.sa_data, dev, sizeof(add.sa_data));
    struct msgARP rplyARP;
    int flag=1;
    do{
        if (sendto(sock, &msgARP, 42, 0, &add, sizeof(add))<=0)  {
            perror("No se pudo enviar ARP request");
            exit(EXIT_FAILURE);
        }
        if (recvfrom(sock, &rplyARP, 42, 0, NULL, NULL)>0){
            
            flag = 0;
        }
    }while(flag);

    struct arp_tbl rply; 

    sprintf(rply.ip_src,"%d.%d.%d.%d",
        rplyARP.destinoIP[0],rplyARP.destinoIP[1],
        rplyARP.destinoIP[2],rplyARP.destinoIP[3]);

    sprintf(rply.ip_dst,"%d.%d.%d.%d",
        rplyARP.origenIP[0],rplyARP.origenIP[1],
        rplyARP.origenIP[2],rplyARP.origenIP[3]);

    sprintf(rply.MAC_dst,"%02X:%02X:%02X:%02X:%02X:%02X",
        rplyARP.origenMAC[0],rplyARP.origenMAC[1],rplyARP.origenMAC[2],
        rplyARP.origenMAC[3],rplyARP.origenMAC[4],rplyARP.origenMAC[5]);

    sprintf(rply.MAC_src,"%02X:%02X:%02X:%02X:%02X:%02X",
        rplyARP.destinoMAC[0],rplyARP.destinoMAC[1],rplyARP.destinoMAC[2],
        rplyARP.destinoMAC[3],rplyARP.destinoMAC[4],rplyARP.destinoMAC[5]);
    sleep(5);
    pthread_mutex_lock(&mutex);
    printf("---Resultados \n");
        printf("IP fuente: %s\t MAC: %s \n",rply.ip_src, rply.MAC_src);
        printf("IP destino: %s\t MAC: %s \n",rply.ip_dst, rply.MAC_dst);
    pthread_mutex_unlock(&mutex);
    struct arp_tbl *ans =  malloc(sizeof(struct arp_tbl)); 
    pthread_exit(ans);
}


