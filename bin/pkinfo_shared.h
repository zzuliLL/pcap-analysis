#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>


#ifndef PKINFO_SHARED_H_
#define PKINFO_SHARED_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned int __u32;
typedef unsigned short __u16;
typedef unsigned char __u8;


/**
*
* @brief PCAP数据包解析后的信息
*
*/
typedef struct pcap_packet_info {
	unsigned int srcip;
	unsigned int dstip;
	unsigned int srcport;
	unsigned int dstport;
	unsigned int proto;
} pcap_packet_info;

typedef struct pcap_packet {
	void *data;               //从PCAP中读取的数据报文，一般是一个完整的以太网帧
	__u32 datasize;           //data的实际数据长度
} pcap_packet;

void *alloc_fun(unsigned int size);
int parse_pcap_date(pcap_packet *pk, pcap_packet_info *pk_info);


#ifdef __cplusplus
}
#endif

#endif //PKINFO_SHARED_H_


