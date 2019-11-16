#include "pcap.h"

/**
 *  PCAP文件的文件头
 */
typedef struct _pcap_file_header {
    __u32 magic;            //主标识:a1b2c3d4
    __u16 version_major;    //主版本号
    __u16 version_minor;    //次版本号
    __u32 thiszone;         //区域时间0
    __u32 sigfigs;          //时间戳0
    __u32 snaplen;          //数据包最大长度
    __u32 linktype;         //链路层类型，取值：DLT_*
} pcap_file_header;

/*
 * These are the types that are the same on all platforms, and that
 * have been defined by <net/bpf.h> for ages.
 */
#define DLT_NULL    0   /* BSD loopback encapsulation */
#define DLT_EN10MB  1   /* Ethernet (10Mb) */
#define DLT_EN3MB   2   /* Experimental Ethernet (3Mb) */
#define DLT_AX25    3   /* Amateur Radio AX.25 */
#define DLT_PRONET  4   /* Proteon ProNET Token Ring */
#define DLT_CHAOS   5   /* Chaos */
#define DLT_IEEE802 6   /* IEEE 802 Networks */
#define DLT_ARCNET  7   /* ARCNET, with BSD-style header */
#define DLT_SLIP    8   /* Serial Line IP */
#define DLT_PPP     9   /* Point-to-point Protocol */
#define DLT_FDDI    10  /* FDDI */


#ifdef __OpenBSD__
#define DLT_RAW     14  /* raw IP */
#else
#define DLT_RAW     12  /* raw IP */
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 0x6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 0x11
#endif

#define IPPROTO     0x800

/**
 *  PCAP文件中数据包所使用的时间戳
 */
typedef struct _pcap_time_stamp {
    __u32 tv_sec;
    __u32 tv_usec;
} pcap_time_stamp;

/**
 *  PCAP文件中数据包的头部
 */
typedef struct _pcap_pkthdr {
    pcap_time_stamp ts;
    __u32 caplen;
    __u32 len;
} pcap_pkthdr;


struct pcap_t {
	FILE *fp;
};

char *g_file_name = NULL;
unsigned short g_mode = 0; // 0轮询 1主动
pcap_t *g_pcap_ptr = NULL;


static void packet_free(pcap_packet *pk)
{
	assert(pk);
	assert(pk->data);
	free(pk->data);
	pk->data = NULL;
	pk->datasize = 0;
}

static void pacp_file_close()
{
	assert(g_pcap_ptr);
	if(g_pcap_ptr->fp == NULL)
		return ;
	fclose(g_pcap_ptr->fp);
	g_pcap_ptr->fp = NULL;
}
static pcap_t* read_pcap_header()
{
	if (g_file_name == NULL)
		return NULL;
	
	FILE *fp = fopen(g_file_name, "rb");
	if (fp == NULL)
	{
		printf("file_name: %s fopen error\n", g_file_name);
		return NULL;
	}
	pcap_file_header pfh;
	
	int cnt = fread(&pfh, sizeof(pcap_file_header), 1, fp);
	if (cnt != 1)
	{
		printf("fread pcap_file_header error\n");
		fclose(fp);
		return NULL;
	}
	pcap_t *pcap_ptr = (pcap_t *)alloc_fun(sizeof(pcap_t));
	pcap_ptr->fp = fp;
	return pcap_ptr;
}

static int read_next_pcap(pcap_packet *pk)
{
	assert(g_pcap_ptr);
	if (g_pcap_ptr->fp == NULL)
		return -1;
	pcap_pkthdr ph;
	int ret = 0;
	
	if (!feof(g_pcap_ptr->fp))
	{
		//printf("feof %d\n", feof(g_pcap_ptr->fp));
		ret = fread(&ph, sizeof(pcap_pkthdr), 1, g_pcap_ptr->fp);
		if (ret != 1)
		{
			printf("feof %d\n", feof(g_pcap_ptr->fp));
			return -1;
		}

		pk->data = alloc_fun(ph.caplen);
		if (fread(pk->data, 1, ph.caplen, g_pcap_ptr->fp) != ph.caplen)
		{
			printf("read ph date error\n");
			packet_free(pk);
			return -1;  //先这样写后面处理用goto
		}
		pk->datasize = ph.caplen;
	}
	return 0;
}

int pcap_init(char *file_name, unsigned short mode)
{
	assert(file_name && file_name[0]);
	assert(mode == 0 || mode == 1);
	
	g_file_name = file_name;
	g_mode = mode;
	g_pcap_ptr = read_pcap_header();
	if (g_pcap_ptr == NULL)
		return -1;
	return 0;
}


void pcap_printf(pcap_packet_info *pk_info)
{
	printf("########################### THE PCAP PACKET######################\n");
	char ip[27];
	inet_ntop(AF_INET, (void *)&(pk_info->srcip), ip, 16);
	printf("srcip = %s\n", ip);
	inet_ntop(AF_INET, (void *)&(pk_info->dstip), ip, 16);
	printf("dstip = %s\n", ip);
	printf("proto = %d\n", pk_info->proto);

	printf("srcport = %d\n", pk_info->srcport);
	printf("dstport = %d\n", pk_info->dstport);
	printf("########################### THE PCAP PACKET######################\n\n");
	
	//printf("the pcap packet is successful\n");
	return ;
}


int next_pcap_cal(pcap_callback cb_filter, void *udata, pcap_show_callback show_pk_info)
{
	if (g_mode == 0)
	{
		printf("g_mode: %d\n", g_mode);
		return -1;
	}
	if (g_pcap_ptr == NULL)
	{
		printf("read_pcap_header error\n");
		return -1;
	}
	int ret = 0;
	
	pcap_packet pk = {0};
	pcap_packet_info pk_info = {0};
	// read date
	if (read_next_pcap(&pk) < 0)
	{
		printf("read_next_pcap error\n");
		return -1;
	}
	
	// 解析
	if (parse_pcap_date(&pk, &pk_info) < 0)
	{
		printf("parse_pcap_date is error!\n");
		return -1;
	}
	
	
	// 过滤
	ret = cb_filter(&pk_info, udata);
	if (ret < 0)
	{
		printf("the pcap packet no match!\n");
		packet_free(&pk);
		return -1;
	}
		
	packet_free(&pk);
	if (ret == 0)
		printf("The pcap packet no match!!!\n");
	else // 满足输出
		show_pk_info(&pk_info);
	
	return 0;
}


// 轮询
int pcap_poll(pcap_callback cb_filter, void *udata, pcap_show_callback show_pk_info)
{
	if (g_mode == 1)
		return -1;
	if (g_pcap_ptr == NULL)
	{
		printf("read_pcap_header error\n");
		return -1;
	}
	int ret = 0;
	
	while(!feof(g_pcap_ptr->fp))
	{
		pcap_packet pk = {0};
		pcap_packet_info pk_info = {0};
		// read date
		if (read_next_pcap(&pk) < 0)
		{
			printf("read_next_pcap error\n");
			break;
		}
		
		// 解析
		if (parse_pcap_date(&pk, &pk_info) < 0)
		{
			printf("parse_pcap_date is error!\n");
			continue;
		}
		
		
		// 过滤
		ret = cb_filter(&pk_info, udata);
		if (ret < 0)
		{
			printf("the pcap packet no match!\n");
			packet_free(&pk);
			continue;
		}
		
		packet_free(&pk);
		if (ret == 0)
			printf("The pcap packet no match!!!\n");
		else // 满足输出
			show_pk_info(&pk_info);
		//break;
		
	}
	return 0;
	
}


int pcap_end()
{
	pacp_file_close();
	return 0;
}









