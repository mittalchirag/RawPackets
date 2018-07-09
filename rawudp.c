#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <time.h>

typedef unsigned char UC;
typedef unsigned short int USI;

#define PCKT_LEN 8192

#define MY_DEST_MAC0 0x00
#define MY_DEST_MAC1 0x01
#define MY_DEST_MAC2 0x02
#define MY_DEST_MAC3 0x03
#define MY_DEST_MAC4 0x04
#define MY_DEST_MAC5 0x05

//Use standard structure form metinet/ip.h and assign new values
//Or we can fabricate our own IP header structure
/*struct myiphdr {
	UC iph_ver:4, iph_ihl:5;
	UC iph_tos;
	USI iph_len;
	USI iph_ident;
	UC iph_flags;
	USI iph_offset;
	UC iph_ttl;
	UC iph_protocol;
	USI iph_chksum;
	u_int iph_source;
	u_int iph_dest;
};

struct myudphdr {
	USI udph_srcport;
	USI udph_destport;
	USI udph_len;
	USI udph_chksum;
};
*/
unsigned short checksum(unsigned short *buf, int nwords){
	unsigned long sum;
	for (sum=0; nwords>0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (unsigned short)(~sum);
}

int totalLength=0;
struct ifreq ifreq_i;
struct ifreq ifreq_mac;
struct ifreq ifreq_ip;
char sendbuf[PCKT_LEN];
struct ether_header *eh=(struct ether_header *)sendbuf;
struct iphdr *iph= (struct iphdr *) (sendbuf + sizeof(struct ether_header));
struct udphdr *udph = (struct udphdr*)(sendbuf + sizeof(struct iphdr) + sizeof(struct ether_header));

int createSocket(char *device){

	int sock_fd;
	sock_fd=socket(PF_PACKET,SOCK_RAW,IPPROTO_RAW);
	if(sock_fd < 0){
		perror("Socket Error");
		exit(-1);
	}
	else{
		printf("Socket Created....\n");
	}

	memset(&ifreq_i, 0, sizeof(ifreq_i));

	strncpy(ifreq_i.ifr_name, device, sizeof(ifreq_i.ifr_name));

	if((ioctl(sock_fd, SIOCGIFINDEX, &ifreq_i))<0){
		perror("SIOCGIFINDEX");
	}

	memset(&ifreq_mac, 0, sizeof(ifreq_mac));

	strncpy(ifreq_mac.ifr_name, device, IFNAMSIZ-1);

	if((ioctl(sock_fd, SIOCGIFHWADDR, &ifreq_mac))<0){
		perror("SIOCGIFHWADDR");
	}

	memset(&ifreq_ip, 0, sizeof(ifreq_ip));

	strncpy(ifreq_ip.ifr_name, device, IFNAMSIZ-1);

	if((ioctl(sock_fd, SIOCGIFADDR, &ifreq_ip))<0){
		perror("SIOCGIFADDR");
	}

	return sock_fd;
}


int constructEthernetHeader(){

	memset(sendbuf, 0 , PCKT_LEN);
	eh->ether_shost[0]= ((uint8_t *)&ifreq_mac.ifr_hwaddr.sa_data)[0];
	eh->ether_shost[1]= ((uint8_t *)&ifreq_mac.ifr_hwaddr.sa_data)[1];
	eh->ether_shost[2]= ((uint8_t *)&ifreq_mac.ifr_hwaddr.sa_data)[2];
	eh->ether_shost[3]= ((uint8_t *)&ifreq_mac.ifr_hwaddr.sa_data)[3];
	eh->ether_shost[4]= ((uint8_t *)&ifreq_mac.ifr_hwaddr.sa_data)[4];
	eh->ether_shost[5]= ((uint8_t *)&ifreq_mac.ifr_hwaddr.sa_data)[5];

	eh->ether_dhost[0]= MY_DEST_MAC0;
	eh->ether_dhost[1]= MY_DEST_MAC1;
	eh->ether_dhost[2]= MY_DEST_MAC2;
	eh->ether_dhost[3]= MY_DEST_MAC3;
	eh->ether_dhost[4]= MY_DEST_MAC4;
	eh->ether_dhost[5]= MY_DEST_MAC5;

	eh->ether_type=htons(ETH_P_IP);

	totalLength += sizeof(struct ether_header);

}


int constructIPHeader(char *saddr, char *daddr){

	iph->ihl=5;
	iph->version=4;
	iph->tos=16;
	iph->id=htons(54321);
	iph->ttl=40;
	iph->protocol=17;
	iph->saddr=inet_addr(saddr);
	iph->daddr=inet_addr(daddr);
	iph->check=checksum((unsigned short*)(sendbuf+ sizeof(struct ether_header)), sizeof(struct iphdr)/2);

	totalLength += sizeof(struct iphdr);
}

int constructUDPHeader(){

	udph->source= htons(3423);
	udph->dest = htons(5432);
	udph->check = 0;

	totalLength += sizeof(struct udphdr);
}

void constructPayload(){
	sendbuf[totalLength++] = 0xde;
	sendbuf[totalLength++] = 0xad;
	sendbuf[totalLength++] = 0xbe;
	sendbuf[totalLength++] = 0xef;
	udph->len=htons(totalLength-sizeof(struct iphdr)-sizeof(struct ether_header));
	iph->tot_len= htons(totalLength-sizeof(struct ether_header));
}


int main(int argc, char* argv[]){

	if(argc!=4){
		printf ("Invalid Parameters!!\n");
		printf ("Usage: %s <interface> <source hostname/IP> <destination hostname/IP>\n",argv[0]);
		exit(-1);
	}

	int sock_fd= createSocket(argv[1]);
	constructEthernetHeader();
	constructIPHeader(argv[2],argv[3]);
	constructUDPHeader();
	constructPayload();

	struct sockaddr_ll socket_address;
	socket_address.sll_ifindex = ifreq_i.ifr_ifindex;
	socket_address.sll_halen = ETH_ALEN;
	socket_address.sll_addr[0]=MY_DEST_MAC0;
	socket_address.sll_addr[1]=MY_DEST_MAC1;
	socket_address.sll_addr[2]=MY_DEST_MAC2;
	socket_address.sll_addr[3]=MY_DEST_MAC3;
	socket_address.sll_addr[4]=MY_DEST_MAC4;
	socket_address.sll_addr[5]=MY_DEST_MAC5;

	if(sendto(sock_fd, sendbuf, totalLength, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll))<0){
		printf ("Send failed\n");
	}

	return 0;
}
