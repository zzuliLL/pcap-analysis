#include "pkinfo_shared.h"

typedef struct IP_HEAD
{
	unsigned char verhlen;  // :4位version, 4位len (<<2) 45H
	unsigned char tos;      // 服务,优先级，正常设为0
	unsigned short len;     // 长度，以字节表示数据报总长度，包括IP 报文头
	unsigned short ident;   // 标识
	unsigned short frags;   // 分段
	unsigned char ttl;      // 生存时间,典型值：100 秒
	unsigned char procotol; // 协议 ,数据域所用协议，比如：1-ICMP 6-TCP，0x11-UDP
	unsigned short crc;     // 校验和,仅仅是IP 头的简单校验和
	unsigned int srcip;     // 4 字节源IP 地址
	unsigned int dstip;     // 4 字节目的IP 地址
} IP_HEAD;


typedef struct TCP_HEAD
{
	unsigned short srcport; //源端口
	unsigned short dstport; //目标端口
	unsigned int seq;
	unsigned int ack;
	unsigned char hlen;     //头部长度
	char notcare[0];        //不关心
} TCP_HEAD;

typedef struct UDP_HEAD
{
	unsigned short srcport;
	unsigned short dstport;
	unsigned short len;
	unsigned short crc;
} UDP_HEAD;

typedef struct PCAP_DATA_HEAD
{
	struct IP_HEAD ip_head;
	int protocol;
	union
	{
		struct TCP_HEAD tcp_head;
		struct UDP_HEAD udp_head;
	} protocol_head;
}PCAP_DATA_HEAD;

void *alloc_fun(unsigned int size)
{
	void *ptr = calloc(1, size);
	if (ptr == NULL)
		abort();
	return ptr;
}


#define DATAGRAM_LEN 14

int parse_pcap_date(pcap_packet *pk, pcap_packet_info *pk_info)
{
	assert(pk && pk->data);
	assert(pk->datasize > 0);
	int len = pk->datasize;
	//printf("len = %d\n", len);
	if (len <= DATAGRAM_LEN)
		return -1;
	len -= DATAGRAM_LEN;
	pk->data += DATAGRAM_LEN;
	PCAP_DATA_HEAD data_head = {0};
	if (len < sizeof(IP_HEAD))
		return -1;
	len -= sizeof(IP_HEAD);
	
	struct IP_HEAD *ip_head_ptr = &data_head.ip_head;
	
	ip_head_ptr->verhlen = *(unsigned char*)pk->data;
	pk->data += sizeof(unsigned char);
	ip_head_ptr->tos = *(unsigned char*)pk->data;
	pk->data += sizeof(unsigned char);
	ip_head_ptr->len = *(unsigned short*)pk->data;
	pk->data += sizeof(unsigned short);
	ip_head_ptr->ident = *(unsigned short*)pk->data;
	pk->data += sizeof(unsigned short);
	ip_head_ptr->frags = *(unsigned short*)pk->data;
	pk->data += sizeof(unsigned short);
	ip_head_ptr->ttl = *(unsigned char*)pk->data;
	pk->data += sizeof(unsigned char);
	ip_head_ptr->procotol = *(unsigned char*)pk->data;
	pk->data += sizeof(unsigned char);
	ip_head_ptr->crc = *(unsigned short*)pk->data;
	pk->data += sizeof(unsigned short);
	ip_head_ptr->srcip = *(unsigned int*)pk->data;
	pk->data += sizeof(unsigned int);
	ip_head_ptr->dstip = *(unsigned int*)pk->data;
	pk->data += sizeof(unsigned int);


	data_head.protocol = ip_head_ptr->procotol;

	pk_info->srcip = ip_head_ptr->srcip;
	pk_info->dstip = ip_head_ptr->dstip;
	pk_info->proto = data_head.protocol;

	/*
	char ip[27];
	inet_ntop(AF_INET, (void *)&(pk_info->srcip), ip, 16);
	printf("srcip = %s\n", ip);
	inet_ntop(AF_INET, (void *)&(pk_info->dstip), ip, 16);
	printf("dstip = %s\n", ip);
	printf("proto = %d\n", pk_info->proto);
	*/
	
	if (ip_head_ptr->procotol == 6 && len > sizeof(struct TCP_HEAD))
	{
		TCP_HEAD tcp_head = {0};
		
		tcp_head.srcport = *(unsigned short*)pk->data;
		pk->data += sizeof(unsigned short);
		tcp_head.dstport = *(unsigned short*)pk->data;
		pk->data += sizeof(unsigned short);
		tcp_head.seq = *(unsigned int*)pk->data;
		pk->data += sizeof(unsigned int);
		tcp_head.ack = *(unsigned int*)pk->data;
		pk->data += sizeof(unsigned int);
		tcp_head.hlen = *(unsigned char*)pk->data;
		pk->data += sizeof(unsigned char);
		data_head.protocol_head.tcp_head = tcp_head;

		len -= 2 * sizeof(unsigned short) + 2 * sizeof(unsigned int) + sizeof(unsigned char);

		pk_info->srcport = ntohs(tcp_head.srcport);
		pk_info->dstport = ntohs(tcp_head.dstport);
	}
	else if(ip_head_ptr->procotol == 0x11 && len > sizeof(struct UDP_HEAD))
	{
		UDP_HEAD udp_head = {0};
	
		udp_head.srcport = *(unsigned short*)pk->data;
		pk->data += sizeof(unsigned short);
		udp_head.dstport = *(unsigned short*)pk->data;
		pk->data += sizeof(unsigned short);
		udp_head.len = *(unsigned short*)pk->data;
		pk->data += sizeof(unsigned short);
		udp_head.crc = *(unsigned short*)pk->data;
		pk->data += sizeof(unsigned short);
		data_head.protocol_head.udp_head = udp_head;

		len -= sizeof(UDP_HEAD);

		pk_info->srcport = ntohs(udp_head.srcport);
		pk_info->dstport = ntohs(udp_head.dstport);
	}
	else
	{
		pk->data -= pk->datasize - len;
		printf("the proto not udp and not tcp, so no care.\n");
		return 0;
	}
	
	pk->data -= pk->datasize - len;
	//printf("srcport = %d\n", pk_info->srcport);
	//printf("dstport = %d\n", pk_info->dstport);
	return 0;
}


