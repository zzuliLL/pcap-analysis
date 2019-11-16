#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <netinet/in.h>

#include "pkinfo_shared.h"


#ifndef PCAP_H_
#define PCAP_H_

#ifdef __cplusplus
extern "C" {
#endif



typedef struct pcap_t pcap_t;

typedef int (*pcap_callback)(pcap_packet_info *pk_info, void *udata);
typedef void (*pcap_show_callback)(pcap_packet_info *pk_info);

int pcap_init(char *file_name, unsigned short mode);
int next_pcap_cal(pcap_callback cb_filter, void *udata, pcap_show_callback show_pk_info);
// 轮询
int pcap_poll(pcap_callback cb_filter, void *udata, pcap_show_callback show_pk_info);
int pcap_end();
void pcap_printf(pcap_packet_info *pk_info);



#ifdef __cplusplus
}
#endif

#endif //PCAP_H_
