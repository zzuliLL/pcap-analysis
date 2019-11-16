#include <stdio.h>
#include "pcap.h"
#include "filter.h"


//---------------------------------------------------------------------------
//  方案1
//---------------------------------------------------------------------------

int main(int argc, char *argv[])
{
	
	pcap_init("/home/sll/pcap/pk/atp.pcap", 0);
	
	// 构造filter

	filter_t * expr = filter_new_not(filter_new_proto(17));

	// 轮询
	pcap_poll(filter_pcap_date, expr, pcap_printf);
	pcap_end();


	/*
	pcap_init("/home/sll/pcap/pk/atp.pcap", 1);
	// 构造filter
	filter_t * expr = filter_new_not(filter_new_proto(17));
	// 主动
	next_pcap_cal(filter_pcap_date, expr);
	pcap_end();
	filter_free(expr);
	*/
	return 0;
}
