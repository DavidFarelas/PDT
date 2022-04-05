/*
	Implementación de un SNIFFER
 	gcc -pthread -o sniffer sniffer.c
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
// Bibliotecas para uso de sockets
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
// Bibliotecas para manejar las estructuras que corresponden a direccionamiento
#include <netinet/in.h>
#include <netdb.h>	
// Bibliotecas para manejo de tramas.
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include<linux/if_packet.h>
#include <linux/ip.h>
// Biblioteca para manejo de hilos con la API POSIX
#include <pthread.h>

#include<malloc.h>
#include<string.h>
#include<signal.h>
#include<stdbool.h>
#include<arpa/inet.h>           

FILE *fp;
unsigned int n_proto[10], n_pack[5];
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

struct frame_buff{
	struct ethhdr eth_header;
	char buff[65536];
	int len;
};

struct ip_list_node{
	char ip_addr[16];
	char ip_addr2[16];
	unsigned int n;
	struct ip_list_node *link;
};

struct ip_list_node *list_ip_src = NULL;
struct ip_list_node *list_ip_dst = NULL;
struct ip_list_node *list_ip_conv = NULL;

void *analize_frame(void *ptr);
void *recv_frame(void *arg);

/* Fundiones para lista de ip */
void count_ip(struct ip_list_node *head, const char* ip_addr);
void count_convers(struct ip_list_node *head, const char* ip_addr1, const char* ip_addr2);
void print_list(struct ip_list_node *head);
void imprime_lista_conv(struct ip_list_node *head);
void print_statics();

int main(int argc, char *argv[]){
	if(argv[1]==NULL|argv[2]==NULL){
		printf("ERROR: Ejecutar con argumentos:\n");
		printf("%s #num_paq nombre_tarj_red\n", argv[0]);
		exit(-1);
	}

	list_ip_src = malloc(sizeof(struct ip_list_node));
	list_ip_src->link = NULL;
	list_ip_dst = malloc(sizeof(struct ip_list_node));
	list_ip_dst->link = NULL;
	list_ip_conv = malloc(sizeof(struct ip_list_node));
	list_ip_conv->link = NULL;

	fp=fopen("sniffer.txt","a+");
    if(fp==NULL){printf("Error al crear el archivo.");}

	pthread_t tid;
	memset(&n_proto,0,sizeof(n_proto));
		
	pthread_create(&tid, NULL, recv_frame, argv);
	pthread_join(tid,NULL);

	/* ----- Estadisticas ----- */
	print_statics();
	system("/sbin/ifconfig wlo1 -promisc");
	return 0;
}

void *recv_frame(void *arg){
	char **argv = (char **)arg;

	long int limit = atol(argv[1]);
	int sock_errno(void), data_size, raw_sock;
	raw_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	/*
		Configurar NIC modo promiscuo:
	*/
	struct ifreq eth;
	strncpy(eth.ifr_name, argv[2], IFNAMSIZ);
	ioctl(raw_sock, SIOCGIFFLAGS, &eth);
	// Operacion or a nivel bit para configurar modo promiscuo
	eth.ifr_flags |= IFF_PROMISC;
	ioctl(raw_sock, SIOCSIFFLAGS, &eth);
	pthread_t tid[limit];
	for (long int i = 0; i < limit; ++i){
		//uint8_t *buffer = malloc(BUF_LENGTH);
		int buf_len = sizeof(struct frame_buff);
		struct frame_buff *buffer=malloc(buf_len);
		data_size = recvfrom(raw_sock, buffer, buf_len, 0, NULL, NULL);
		buffer->len = data_size;
		if(data_size>0){
			pthread_create(&tid[i], NULL, analize_frame, buffer);
		}else{free(buffer);}
	}
	for (long int i = 0; i < limit; ++i){
		pthread_join(tid[i], NULL);
	}
	close(raw_sock);

}

void *analize_frame(void *ptr){
	struct frame_buff *buff =(struct frame_buff*)ptr;
	struct ethhdr header = buff->eth_header;
	int len = buff->len;
	uint8_t buffer[len-14];
	for (int i = 0; i <=len-14; ++i)
		buffer[i]=buff->buff[i];
	free(buff);
	struct iphdr *ip = (struct iphdr*)(buffer);
	struct sockaddr_in source,dest;
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = ip->saddr;     
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = ip->daddr;  
	char ip_src[16], ip_dst[16];

	sprintf(ip_src,"%s",inet_ntoa(source.sin_addr));
	sprintf(ip_dst,"%s",inet_ntoa(dest.sin_addr));

	header.h_proto = htons(header.h_proto);
	char p_type[10];
	if(header.h_proto == ETH_P_IP){
		switch((unsigned int)ip->protocol){
			case 0x01:
				sprintf(p_type,"ICMPv4");
				pthread_mutex_lock(&mutex);
				n_proto[0] +=1;
				pthread_mutex_unlock(&mutex);
				break;
			case 0x02:
				sprintf(p_type,"IGMP");
				pthread_mutex_lock(&mutex);
				n_proto[1] +=1;
				pthread_mutex_unlock(&mutex);
				break;
			case 0x04:
				sprintf(p_type,"IP");
				pthread_mutex_lock(&mutex);
				n_proto[2] +=1;
				pthread_mutex_unlock(&mutex);
				break;
			case 0x06:
				sprintf(p_type,"TCP");
				pthread_mutex_lock(&mutex);
				n_proto[3] +=1;
				pthread_mutex_unlock(&mutex);
				break;
			case 0x11:
				sprintf(p_type,"UDP");
				pthread_mutex_lock(&mutex);
				n_proto[4] +=1;
				pthread_mutex_unlock(&mutex);
				break;
			case 0x29:
				sprintf(p_type,"IPv6");
				pthread_mutex_lock(&mutex);
				n_proto[5] +=1;
				pthread_mutex_unlock(&mutex);
				break;
			case 0x59:
				sprintf(p_type,"OSPF");
				pthread_mutex_lock(&mutex);
				n_proto[6] +=1;
				pthread_mutex_unlock(&mutex);
				break;
			default:
				sprintf(p_type,"Unidentified");
				pthread_mutex_lock(&mutex);
				n_proto[7] +=1;
				pthread_mutex_unlock(&mutex);
		}

		if(ntohs(ip->tot_len)<160){
			pthread_mutex_lock(&mutex);
			n_pack[0] += 1;
			pthread_mutex_unlock(&mutex);
		}else if(ntohs(ip->tot_len)<640){
			pthread_mutex_lock(&mutex);
			n_pack[1] += 1;
			pthread_mutex_unlock(&mutex);
		}else if(ntohs(ip->tot_len)<1280){
			pthread_mutex_lock(&mutex);
			n_pack[2] += 1;
			pthread_mutex_unlock(&mutex);
		}else if(ntohs(ip->tot_len)<5120){
			pthread_mutex_lock(&mutex);
			n_pack[3] += 1;
			pthread_mutex_unlock(&mutex);
		}else{
			pthread_mutex_lock(&mutex);
			n_pack[4] += 1;
			pthread_mutex_unlock(&mutex);
		}

		/* --------- lista --------*/
		pthread_mutex_lock(&mutex);
		count_ip(list_ip_src, ip_src);
		pthread_mutex_unlock(&mutex);

		pthread_mutex_lock(&mutex);
		count_ip(list_ip_dst, ip_dst);
		pthread_mutex_unlock(&mutex);

		pthread_mutex_lock(&mutex);
		count_convers(list_ip_conv, ip_src, ip_dst);
		pthread_mutex_unlock(&mutex);

		pthread_mutex_lock(&mutex);
		fprintf(fp,"\n");
		fprintf(fp,"\n------ IP HEADER -------\n");
		fprintf(fp,"\t|-Dirección IP fuente........: %s\n", ip_src);
		fprintf(fp,"\t|-Dirección IP destino.......: %s\n", ip_dst);
		fprintf(fp,"\t|-Longitud de cabecera.......: %d Bytes\n", ((unsigned int)(ip->ihl))*4);
		fprintf(fp,"\t|-Longitud total datagrama...: %d Bytes\n", ntohs(ip->tot_len));
		fprintf(fp,"\t|-Identificador del datagrama: %d\n", ntohs(ip->id));
		fprintf(fp,"\t|-Tiempo de vida.............: %d\n", (unsigned int)ip->ttl);
		fprintf(fp,"\t|-Protocolo de capa superior.: 0x%02x (%s)\n", (unsigned int)ip->protocol,p_type);
		fprintf(fp,"Longitud de carga útil: %d Bytes\n", ntohs(ip->tot_len)-((unsigned int)(ip->ihl))*4);
		fprintf(fp,"Tipo de servicio utilizado: 0x%02x\n", (unsigned int)ip->tos);
		fprintf(fp,"Campos relacionados con la fragmentación 0x%04x\n", ntohs(ip->frag_off));

		if((ntohs(ip->frag_off) & 0x8000)>0){
			fprintf(fp,"\tBandera de fragmento reservada activa\n");
		}else if((ntohs(ip->frag_off) & 0x4000)>0){
			fprintf(fp,"\tEl datagrama no se puede fragmentar \n");	
		}else if(ntohs(ip->frag_off & 0x2000)>0){
			fprintf(fp,"\tBandera de mas fragmentos activa\n");
			if(ntohs(ip->frag_off & 0x1FFF)==0)
				fprintf(fp,"\t\tPrimer Fragmento\n");
			else
				fprintf(fp,"\t\tFragmento intermedio\n");
		}else if(ntohs(ip->frag_off & 0x1FFF)>0){
			fprintf(fp,"\t\tÚltimo fragmento\n");
		}else{// 0x0000
			fprintf(fp, "\t\tFragmento único\n");
		}

		fprintf(fp,"Primer Byte: 0x%02x\tUltimo Byte: 0x%02x\n",buffer[0], buffer[(ntohs(ip->tot_len))-1]);
		fprintf(fp,"\n");
		pthread_mutex_unlock(&mutex);
	}
	pthread_exit(NULL);
}

void count_ip(struct ip_list_node *head, const char* ip_addr){
	if(head == NULL){
		printf("lista vacía\n");
		return;
	}
	struct ip_list_node *ptr = NULL;
	struct ip_list_node *ptr2 = NULL;
	ptr = head;
	while(ptr != NULL){
		if(strcmp(ptr->ip_addr,ip_addr)==0){
			ptr->n += 1;
			return;
		}else if(ptr->n == 0){
			sprintf(ptr->ip_addr, ip_addr);
			ptr->n += 1;
			return;
		}
		ptr2 = ptr;
		ptr = ptr->link;
	}
	struct ip_list_node *temp ;
	temp = malloc(sizeof(struct ip_list_node));
	sprintf(temp->ip_addr, ip_addr);
	temp->n = 1; 
	temp->link = NULL;
	ptr2->link = temp;
	return;
}

void count_convers(struct ip_list_node *head, const char* ip_addr1, const char* ip_addr2){
	if(head == NULL){
		printf("lista vacía\n");
		return;
	}
	struct ip_list_node *ptr = NULL;
	struct ip_list_node *ptr2 = NULL;
	ptr = head;
	while(ptr != NULL){
		if((strcmp(ptr->ip_addr, ip_addr1)==0)&&(strcmp(ptr->ip_addr2, ip_addr2)==0)){
			ptr->n += 1;
			return;
		}else if((strcmp(ptr->ip_addr, ip_addr2)==0)&&(strcmp(ptr->ip_addr2, ip_addr1)==0)){
			ptr->n += 1;
			return;
		}else if(ptr->n == 0){
			sprintf(ptr->ip_addr, ip_addr1);
			sprintf(ptr->ip_addr2, ip_addr2);
			ptr->n = 1;
			return;
		}
		ptr2 = ptr;
		ptr = ptr->link;
	}
	struct ip_list_node *temp;
	temp = malloc(sizeof(struct ip_list_node));
	sprintf(temp->ip_addr, ip_addr1);
	sprintf(temp->ip_addr2, ip_addr2);
	temp->n = 1;
	temp->link = NULL;
	ptr2->link = temp;
	return;
}

void print_list(struct ip_list_node *head){
	if(head == NULL)
		printf("lista vacía\n");
	struct ip_list_node *ptr = NULL;
	ptr= head;
	while(ptr!= NULL){
		printf("\n\t|-#%d IP:%s",ptr->n, ptr->ip_addr );
		fprintf(fp,"\n\t|-#%d IP:%s",ptr->n, ptr->ip_addr );
		ptr = ptr->link;
	}
}

void imprime_lista_conv(struct ip_list_node *head){
	if(head == NULL)
		printf("lista vacía\n");
	struct ip_list_node *ptr = NULL;
	ptr= head;
	while(ptr!= NULL){
		printf("\n\t|-#%d Paquetes entre IP:%s y IP:%s",ptr->n, ptr->ip_addr, ptr->ip_addr2);
		fprintf(fp,"\n\t|-#%d Paquetes entre IP:%s y IP:%s",ptr->n, ptr->ip_addr, ptr->ip_addr2);
		ptr = ptr->link;
	}
}

void print_statics(){
	fprintf(fp,"\n----- Estadisticas -----");
	fprintf(fp,"\n\n Número de paquetes capturados de cada uno de los protocolos de capa superior:");
	fprintf(fp,"\n\t|-ICMPv4:       %d",n_proto[0]);
	fprintf(fp,"\n\t|-IGMP:         %d",n_proto[1]);
	fprintf(fp,"\n\t|-IP:           %d",n_proto[2]);
	fprintf(fp,"\n\t|-TCP:          %d",n_proto[3]);
	fprintf(fp,"\n\t|-UDP:          %d",n_proto[4]);
	fprintf(fp,"\n\t|-IPv6:         %d",n_proto[5]);
	fprintf(fp,"\n\t|-OSPF:         %d",n_proto[6]);
	fprintf(fp,"\n\t|-Unidentified: %d",n_proto[7]);

	printf("\n----- Estadisticas -----\n");
	printf("\n Número de paquetes capturados de cada uno de los protocolos de capa superior:");
	printf("\n\t|-ICMPv4:       %d",n_proto[0]);
	printf("\n\t|-IGMP:         %d",n_proto[1]);
	printf("\n\t|-IP:           %d",n_proto[2]);
	printf("\n\t|-TCP:          %d",n_proto[3]);
	printf("\n\t|-UDP:          %d",n_proto[4]);
	printf("\n\t|-IPv6:         %d",n_proto[5]);
	printf("\n\t|-OSPF:         %d",n_proto[6]);
	printf("\n\t|-Unidentified: %d",n_proto[7]);

	printf("\n\nDirecciones IP (fuente) repetidas:");
	fprintf(fp,"\n\nDirecciones IP (fuente) repetidas:");
	print_list(list_ip_src);

	printf("\n\nDirecciones IP (destino) repetidas:");
	fprintf(fp,"\n\nDirecciones IP (destino) repetidas:");
	print_list(list_ip_dst);

	printf("\n\nNúmero de paquetes transmitiidos entre dos hosts especificos (conversaciones): ");
	fprintf(fp,"\n\nNúmero de paquetes transmitiidos entre dos hosts especificos (conversaciones):");
	imprime_lista_conv(list_ip_conv);

	fprintf(fp,"\n\n Número de paquetes segun su tamaño:");
	fprintf(fp,"\n\t|0-159:        %d",n_pack[0]);
	fprintf(fp,"\n\t|160-639:      %d",n_pack[1]);
	fprintf(fp,"\n\t|640-1279:     %d",n_pack[2]);
	fprintf(fp,"\n\t|1280-5119:    %d",n_pack[3]);
	fprintf(fp,"\n\t|5120 o mayor: %d",n_pack[4]);

	printf("\n\n Número de paquetes segun su tamaño:");
	printf("\n\t|0-159:        %d",n_pack[0]);
	printf("\n\t|160-639:      %d",n_pack[1]);
	printf("\n\t|640-1279:     %d",n_pack[2]);
	printf("\n\t|1280-5119:    %d",n_pack[3]);
	printf("\n\t|5120 o mayor: %d",n_pack[4]);
	printf("\n\n");
}