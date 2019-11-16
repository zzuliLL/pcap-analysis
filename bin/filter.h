#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <netinet/in.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>


#include "pcap.h"
#include "pkinfo_shared.h"


#ifndef FILTER_H_
#define FILTER_H_

#ifdef __cplusplus
extern "C" {
#endif


typedef struct filter_t filter_t;
typedef int (*pcap_filter_callback)(pcap_packet *pk, void *udata, pcap_packet_info *pkinfo);

int filter_get_data(filter_t *expr);
filter_t *filter_get_lhs(filter_t *expr);
filter_t *filter_get_rhs(filter_t *expr);
filter_t *filter_new_or(filter_t *lhs, filter_t *rhs);      //创建一个进行或计算的过滤表达式
filter_t *filter_new_and(filter_t *lhs, filter_t *rhs);     //创建一个进行与计算的过滤表达式
filter_t *filter_new_not(filter_t *expr);                   //创建一个进行非运算的过滤表达式
filter_t *filter_new_srcport(int port);                     //创建一个匹配源端口的过滤表达式
filter_t *filter_new_dstport(int port);                     //创建一个匹配目端口的过滤表达式
filter_t *filter_new_srcip(unsigned int ip);                         //创建一个匹配源IP的过滤表达式
filter_t *filter_new_dstip(unsigned int ip);                         //创建一个匹配目IP的过滤表达式
filter_t *filter_new_proto(int proto);                      //创建一个匹配协议的过滤表达式
int filter_free(filter_t *expr);                           //释放过滤表达式

int filter_pcap_date(pcap_packet_info *pk_info, void *udata);


#ifdef __cplusplus
}
#endif

#endif //FILTER_H_
