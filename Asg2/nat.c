#ifndef __NFT_MAIN

#define __NFT_MAIN

/*
 * nftest.c
 * - demo program of netfilter_queue
 * - Patrick P. C. Lee
 *
 * - To run it, you need to be in root
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <time.h>

#include <linux/types.h>
#include <linux/netfilter.h>
#include <netinet/ip.h>		// required by "struct iph"
#include <netinet/tcp.h>	// required by "struct tcph"
#include <netinet/udp.h>	// required by "struct udph"
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <sys/types.h>			// required by "inet_ntop()"
#include <sys/socket.h>			// required by "inet_ntop()"
#include <arpa/inet.h>			// required by "inet_ntop()"

#include "checksum.h"

#define MAX 2001
#define tableMAX 2000
#define UDP_TIMEOUT 30

#define TCP_INIT_STATE 0xFF

#define TCP_STATE_IN_FIN1	0x01
#define TCP_STATE_OUT_ACK1	0x02
#define TCP_STATE_OUT_FIN2	0x03

#define TCP_STATE_OUT_FIN1	0x11
#define TCP_STATE_IN_ACK1	0x12
#define TCP_STATE_IN_FIN2	0x13

#endif

/****** Global Variables ******/

typedef struct UDP_Table{
	uint32_t ipAddr; //vm b or c
	uint16_t port; 	//vm b or c
	uint16_t translated_port; //vm a
	double timestamp;
	char valid;
}UDP_Table;

typedef struct TCP_Table{
	unsigned int originalIP;
	unsigned short originalPort;
	unsigned short newPort;
	unsigned char  state;
	int valid;
}TCP_Table;

struct iphdr *ip; 
struct tcphdr *tcp;
struct udphdr *udp;
nfqnl_msg_packet_hdr *ph;

UDP_Table UDP_NAT_TABLE[MAX];
TCP_Table TCP_NAT_TABLE[MAX];
char UDP_PORTARRY[2001];
char TCP_PORTARRY[2001];

time_t pTime;

uint32_t pIP;
uint32_t lanIP;
uint32_t lanMask;
unsigned int mask = 0xFFFFFFFF;
int packet_num = 0;

int UDP_Handling(struct nfq_q_handle *qh,u_int32_t id,int payload_len,unsigned char *payloadData);
int TCP_Handling(struct nfq_q_handle *qh,u_int32_t id,int payload_len,unsigned char *payloadData);
void checkUDPValid();

/****** Callback ******/

static int Callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    printf("Entering callback poi\n");

    int payload_len;
    unsigned char *payloadData;
    unsigned short ipCheck, udpCheck, tcpCheck;

    ph = nfq_get_msg_packet_hdr(nfa);
    u_int32_t id = ntohl(ph->packet_id);
    payload_len = nfq_get_payload(nfa, &payloadData);

    ip = (struct iphdr *)payloadData;

	pTime = time(NULL);
    printf("pTime:%ld \n",pTime);

    packet_num++;

    checkUDPValid();

	switch(ip->protocol)
	{
		case IPPROTO_TCP:
		printf("Received a TCP packet\n");
		tcp = (struct tcphdr *)(payloadData + (ip->ihl<<2));
		TCP_Handling(qh,id,payload_len, payloadData);
		break;

		case IPPROTO_UDP:
		printf("Received a UDP packet\n");
		udp = (struct udphdr *)(payloadData + (ip->ihl<<2));
		UDP_Handling(qh,id,payload_len, payloadData);
		break;

		default:
		printf("Unsupported protocol packet dropped\n");
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}

	printf("--^Packet number[%d]-------------------\n",packet_num);
	return 0;
}

void checkUDPValid(){
	int i;
	for(i=0;i<tableMAX;i++)
	{
		if(UDP_NAT_TABLE[i].valid==1){
			if(pTime - UDP_NAT_TABLE[i].timestamp > UDP_TIMEOUT){
				UDP_NAT_TABLE[i].valid=0;
				printf("port %d expired, changed valid to 0.\n",i+10000);
			}
		}
	}
}

int OutRecordUDP(uint32_t ip_temp,uint16_t port_temp){
	int i;
	int match_index = -1;

	printf("OutRecordUDP sIP:%u\n",ip_temp);
	printf("OutRecordUDP sPort:%u\n",port_temp);

	for(i=0;i<tableMAX;i++)
	{
		if((ip_temp==UDP_NAT_TABLE[i].ipAddr)&&(port_temp==UDP_NAT_TABLE[i].port)){
			if(UDP_NAT_TABLE[i].valid==1){
				match_index=i;
				printf("After UDP out-bound match_index: %d \n",match_index);		fflush(stdout);
				break;
			}
		}
	}

	if (match_index != -1)
	{
		return match_index;
	} else {
		return -1;
	}
}

int InRecordUDP(uint16_t port_temp){
	int i;
	int match,match_index = 0;

	printf("InRecordUDP:%u    ",port_temp);

	for(i=0;i<tableMAX;i++)
	{
		if((port_temp==UDP_NAT_TABLE[i].translated_port)&&(UDP_NAT_TABLE[i].valid==1))
			{
				match = 1;
				match_index=i;
				break;
			}
	}

	printf("InRecordUDP match_index:%d.\n",match_index);

	if(match == 1){
		return match_index;
	} else {
		return -1;
	}
}

int addRecordUDP(uint32_t ip_temp, uint16_t port_temp){
	printf("UDP out-bound Doesn't MATCH \n");
	unsigned short translated_port_temp=0;

	int i;
	for(i=0;i<2001;i++)
	{
		if(UDP_NAT_TABLE[i].valid==0)
		{
			UDP_NAT_TABLE[i].valid=1;
			translated_port_temp=10000+i;
			break;
		}

	}

	if(translated_port_temp==0)
	{
		return -1;
	}

	printf("UDP out-bound i:%d\n",i);
	printf("UDP out-bound Create new entry: translated_port %d\n",translated_port_temp);		fflush(stdout);
	printf("UDP out-bound translate to port:  %d\n",translated_port_temp);		fflush(stdout);


	UDP_NAT_TABLE[i].ipAddr=ip_temp;
	printf("UDP_NAT_TABLE[i].ipAddr:%u \n",UDP_NAT_TABLE[i].ipAddr);
	UDP_NAT_TABLE[i].port=port_temp;
	printf("UDP_NAT_TABLE[i].port:%u \n",UDP_NAT_TABLE[i].port);
	UDP_NAT_TABLE[i].translated_port=translated_port_temp;
	UDP_NAT_TABLE[i].valid=1;

	time_t ts = time(NULL);

	UDP_NAT_TABLE[i].timestamp=ts;

	return translated_port_temp;
}

int UDP_Handling(struct nfq_q_handle *qh,u_int32_t id,int payload_len,unsigned char *payloadData){
	uint32_t sIP, dIP;
	uint16_t sPort, dPort, transPort;

	// get IPs
	sIP = ntohl(ip->saddr);
	dIP = ntohl(ip->daddr);

	// get ports
	sPort = ntohs(udp->source);
	dPort = ntohs(udp->dest);

	if ((sIP & mask) == lanMask) {
		puts("outbound");
		int entry = OutRecordUDP(sIP, sPort);
		printf("sIP:%u\n",sIP);
		printf("sPort:%u\n",sPort);
		if (entry == -1) {
			puts("not found");

			transPort = addRecordUDP(sIP, sPort);
			if(transPort == -1){
				printf("No available port,packet droped\n");
				return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
			}
		} else {
			puts("found");

			// check is expired
			if ((pTime - UDP_NAT_TABLE[entry].timestamp) <= UDP_TIMEOUT) {
				UDP_NAT_TABLE[entry].timestamp = pTime;
				transPort = UDP_NAT_TABLE[entry].translated_port;
				printf("found transPort:%u \n",transPort);

			} else {
				transPort = addRecordUDP(sIP, sPort);
				UDP_NAT_TABLE[entry].valid = 0;
				printf("found but timeout transPort:%u \n",transPort);
			}
		}

		// change source IP:port
		ip->saddr = htonl(pIP);
		udp->source = htons(transPort);

		// reset checksum
		ip->check = 0;
		udp->check = 0;

		// calculate new checksum
		udp->check = udp_checksum((unsigned char *) ip);
		ip->check = ip_checksum((unsigned char *) ip);

		// send out packet
		return nfq_set_verdict(qh, id, NF_ACCEPT, payload_len, payloadData);

	}else {
		puts("inbound");

		// check record exists
		int entry = InRecordUDP(dPort);
		if (entry == -1) {
			puts("not found");

			// drop packet
			return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
		} else {
			puts("found");

			if ((pTime - UDP_NAT_TABLE[entry].timestamp) >= UDP_TIMEOUT) {
				printf("port expired, drop packet.\n");
				return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
			}

			// change destination IP:port
			ip->daddr = htonl(UDP_NAT_TABLE[entry].ipAddr);
			udp->dest = htons(UDP_NAT_TABLE[entry].port);

			// reset checksum
			ip->check = 0;
			udp->check = 0;

			// calculate new checksum
			udp->check = udp_checksum((unsigned char *) ip);
			ip->check = ip_checksum((unsigned char *) ip);

			// send out packet
			return nfq_set_verdict(qh, id, NF_ACCEPT, payload_len, payloadData);
		}
	}	

}

void clearEntry(int entry){
	TCP_NAT_TABLE[entry].valid = 0;
	int port;
	port = TCP_NAT_TABLE[entry].newPort - 10000;
	TCP_PORTARRY[port] = 0;
	printf("Changed TCP_PORTARRY[%d] to 0. \n",port);
	return;
}

int TCPfindport(){
	int i;
	int newPort = -1;
	for(i=0;i<2001;i++){
		if(TCP_PORTARRY[i] == 0){
				TCP_PORTARRY[i]=1;
				newPort = (i+10000);
				break;
		}
	}
	return newPort;
}

int TCP_Handling(struct nfq_q_handle *qh,u_int32_t id,int payload_len,unsigned char *payloadData){
	uint32_t sIP, dIP;
	uint16_t sPort, dPort, transPort;
	int i, entry;

	// get IPs
	sIP = ntohl(ip->saddr);
	dIP = ntohl(ip->daddr);

	// get ports
	sPort = ntohs(tcp->source);
	dPort = ntohs(tcp->dest);

	// in/out bound
	if ((sIP & mask) == lanMask) {
		puts("outbound");

		// check record exists
		entry = -1;
		for(i=0;i<tableMAX;i++){
			if(TCP_NAT_TABLE[i].valid == 1){
				if((TCP_NAT_TABLE[i].originalIP == sIP) && (TCP_NAT_TABLE[i].originalPort == sPort)){
					entry = i;
					break;
				}
			}
		}

		if(entry == -1){
			puts("not found");

			if(tcp->syn == 1){
				printf("Received a SYN packet && Not found in Table Entry\n");
				int newPort = TCPfindport();
				if(newPort == -1){
					printf("No new Port available!\n");
					return -1;
				} else {
					int insertEntry = -1;
					for(i=0;i<tableMAX;i++){
						if(TCP_NAT_TABLE[i].valid == 0){
							insertEntry = i;
							break;
						}
					}
					if(insertEntry == -1){
						printf("Warning! There is no empty entry to be inserted!!\n");
						return -1;
					}

					TCP_NAT_TABLE[insertEntry].originalIP = ntohl(ip->saddr);
					TCP_NAT_TABLE[insertEntry].originalPort = ntohs(tcp->source);
					TCP_NAT_TABLE[insertEntry].newPort = newPort;
					TCP_NAT_TABLE[insertEntry].state = TCP_INIT_STATE;
					TCP_NAT_TABLE[insertEntry].valid = 1;
					printf("Created new Entry table! NewPort: %d\n",newPort);

				}
			} else {
				printf("Received Not a SYN packet && Not found in Table Entry\n");
				printf("Drop the packet!\n");
				return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
			}
		} else {
			puts("found");

			transPort = TCP_NAT_TABLE[entry].newPort;
			if (tcp->rst) {
				clearEntry(entry);
				entry = -1;
			}

			if (entry != -1) {
				switch (TCP_NAT_TABLE[entry].state) {
					case TCP_INIT_STATE:
						if (tcp->fin) TCP_NAT_TABLE[entry].state = TCP_STATE_OUT_FIN1;
						break;
					case TCP_STATE_IN_FIN2:
						if (tcp->ack) clearEntry(entry);
						else puts("4-way handshake error, expected out ACK2");
						break;
					case TCP_STATE_IN_FIN1:
						if (tcp->ack) TCP_NAT_TABLE[entry].state = TCP_STATE_OUT_ACK1;
						else puts("4-way handshake error, expected out ACK1");
						if (tcp->ack && tcp->fin) TCP_NAT_TABLE[entry].state = TCP_STATE_OUT_FIN2;
						break;
					case TCP_STATE_OUT_ACK1:
						if (tcp->fin) TCP_NAT_TABLE[entry].state = TCP_STATE_OUT_FIN2;
						else puts("4-way handshake error, expected out FIN2");
						break;
					default:
						printf("%x\n", TCP_NAT_TABLE[entry].state);
						puts("TCP state error");
				}
			}
		}

		// change source IP:port
		ip->saddr = htonl(pIP);
		tcp->source = htons(transPort);

		// reset checksum
		ip->check = 0;
		tcp->check = 0;

		// calculate new checksum
		tcp->check = tcp_checksum((unsigned char *) ip);
		ip->check = ip_checksum((unsigned char *) ip);

		// send out packet
		return nfq_set_verdict(qh, id, NF_ACCEPT, payload_len, payloadData);

	} else {
		puts("inbound");

		entry = -1;
		for(i=0;i<tableMAX;i++){
			if(TCP_NAT_TABLE[i].valid == 1){
				if(TCP_NAT_TABLE[i].newPort == dPort){
					entry = i;
					break;
				}
			}
		}

		if (entry == -1) {
			puts("not found , drop packet");

			// drop packet
			return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
		} else {
			puts("found");

			// change destination IP:port
			ip->daddr = htonl(TCP_NAT_TABLE[entry].originalIP);
			tcp->dest = htons(TCP_NAT_TABLE[entry].originalPort);

			// check is RST
			if (tcp->rst) {
				clearEntry(entry);
				entry = -1;
			}

			if (entry != -1) {
				switch (TCP_NAT_TABLE[entry].state) {
					case TCP_INIT_STATE:
						if (tcp->fin) TCP_NAT_TABLE[entry].state = TCP_STATE_IN_FIN1;
						break;
					case TCP_STATE_OUT_FIN2:
						if (tcp->ack) clearEntry(entry);
						else puts("4-way handshake error, expected in ACK2");
						break;
					case TCP_STATE_OUT_FIN1:
						if (tcp->ack) TCP_NAT_TABLE[entry].state = TCP_STATE_IN_ACK1;
						else puts("4-way handshake error, expected in ACK1");
						if (tcp->ack && tcp->fin) TCP_NAT_TABLE[entry].state = TCP_STATE_IN_FIN2;
						break;
					case TCP_STATE_IN_ACK1:
						if (tcp->fin) TCP_NAT_TABLE[entry].state = TCP_STATE_IN_FIN2;
						else puts("4-way handshake error, expected in FIN2");
						break;
					default:
						printf("%x\n", TCP_NAT_TABLE[entry].state);
						puts("TCP state error");
				}
			}
		}

		// reset checksum
		ip->check = 0;
		tcp->check = 0;

		// calculate new checksum
		tcp->check = tcp_checksum((unsigned char *) ip);
		ip->check = ip_checksum((unsigned char *) ip);

		return nfq_set_verdict(qh, id, NF_ACCEPT, payload_len, payloadData);

	}
}


/*
 * Main program
 */
int main(int argc, char **argv) {

	struct nfq_q_handle *myQueue;
	struct nfnl_handle *netlinkHandle;
	struct nfq_handle *nfqHandle;

	int fd, res;
	char buf[4096];
	struct in_addr container;

	if(argc!=4)
	{
		printf("Usage: ./nat [public IP] [internal IP] [netmask] \n");
		exit(0);
	}

	// process argument
	inet_aton(argv[1],&container);
	pIP = ntohl(container.s_addr);				//public IP
	inet_aton(argv[2],&container);
	lanIP = ntohl(container.s_addr);				//LAN IP
	mask = mask << (32 - atoi(argv[3]));	//subnet mask
	lanMask = lanIP & mask;					//subnet IP

	// Get a queue connection handle from the module
	if (!(nfqHandle = nfq_open())) {
		fprintf(stderr, "Error in nfq_open()\n");
		exit(-1);
	}

	// Unbind the handler from processing any IP packets 
	// (seems to be a must)
	if (nfq_unbind_pf(nfqHandle, AF_INET) < 0) {
		fprintf(stderr, "Error in nfq_unbind_pf()\n");
		exit(1);
	}

	// Bind this handler to process IP packets...
	if (nfq_bind_pf(nfqHandle, AF_INET) < 0) {
		fprintf(stderr, "Error in nfq_bind_pf()\n");
		exit(1);
	}

	// Install a callback on queue 0
	if (!(myQueue = nfq_create_queue(nfqHandle,  0, &Callback, NULL))) {
		fprintf(stderr, "Error in nfq_create_queue()\n");
		exit(1);
	}

	// Turn on packet copy mode
	if (nfq_set_mode(myQueue, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "Could not set packet copy mode\n");
		exit(1);
	}

	netlinkHandle = nfq_nfnlh(nfqHandle);
	fd = nfnl_fd(netlinkHandle);

	printf("Start handleing packet...\n");

	while ((res = recv(fd, buf, sizeof(buf), 0)) && res >= 0) {
		// I am not totally sure why a callback mechanism is used
		// rather than just handling it directly here, but that
		// seems to be the convention...
		nfq_handle_packet(nfqHandle, buf, res);
		// end while receiving traffic
	}

	nfq_destroy_queue(myQueue);

	nfq_close(nfqHandle);

	return 0;

	// end main
}
