#include <stdio.h>
#include "pcap.h"
#include "filter.h"
#include "gtest/gtest.h"

int main(int argc, char *argv[])
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}


TEST(pcap_init, init1)
{
	EXPECT_EQ(0, pcap_init("/home/sll/pcap/pk/atp.pcap", 0));
	pcap_end();
}


TEST(pcap_init, init2)
{
	EXPECT_EQ(-1, pcap_init("/home/sll/pcap/aaaa.pcap", 0));
}



TEST(pcap_end, end1)
{
	EXPECT_EQ(0, pcap_init("/home/sll/pcap/pk/atp.pcap", 0));
	EXPECT_EQ(0, pcap_end());
}



TEST(pcap_poll, poll1)
{
	EXPECT_EQ(0, pcap_init("/home/sll/pcap/pk/atp.pcap", 0));
	// 构造filter
	filter_t * expr = filter_new_dstport(68);
	// 轮询
	ASSERT_EQ(0, pcap_poll(filter_pcap_date, expr, pcap_printf));
	
	EXPECT_EQ(0, pcap_end());
	filter_free(expr);
}


TEST(pcap_poll, poll2)
{
	EXPECT_EQ(0, pcap_init("/home/sll/pcap/pk/atp.pcap", 0));
	// 构造filter
	filter_t * expr = filter_new_srcport(68);
	// 轮询
	ASSERT_EQ(0, pcap_poll(filter_pcap_date, expr, pcap_printf));
	
	EXPECT_EQ(0, pcap_end());
	filter_free(expr);
}


TEST(pcap_poll, poll3)
{
	EXPECT_EQ(0, pcap_init("/home/sll/pcap/pk/atp.pcap", 0));
	// 构造filter
	filter_t * expr = filter_new_srcip(272812232);
	// 轮询
	ASSERT_EQ(0, pcap_poll(filter_pcap_date, expr, pcap_printf));
	EXPECT_EQ(0, pcap_end());
	filter_free(expr);
}


TEST(pcap_poll, poll4)
{
	EXPECT_EQ(0, pcap_init("/home/sll/pcap/pk/atp.pcap", 0));
	// 构造filter
	filter_t * expr = filter_new_dstip(4227858656);
	// 轮询
	ASSERT_EQ(0, pcap_poll(filter_pcap_date, expr, pcap_printf));
	EXPECT_EQ(0, pcap_end());
	filter_free(expr);
}

TEST(pcap_poll, poll5)
{
	EXPECT_EQ(0, pcap_init("/home/sll/pcap/pk/atp.pcap", 0));
	// 构造filter
	filter_t * expr = filter_new_proto(17);
	// 轮询
	ASSERT_EQ(0, pcap_poll(filter_pcap_date, expr, pcap_printf));
	EXPECT_EQ(0, pcap_end());
	filter_free(expr);
}

TEST(pcap_poll, poll6)
{
	EXPECT_EQ(0, pcap_init("/home/sll/pcap/pk/atp.pcap", 0));
	// 构造filter
	filter_t * expr = filter_new_and(filter_new_proto(17), filter_new_srcport(137));
	// 轮询
	ASSERT_EQ(0, pcap_poll(filter_pcap_date, expr, pcap_printf));
	EXPECT_EQ(0, pcap_end());
	filter_free(expr);
}

TEST(pcap_poll, poll7)
{
	EXPECT_EQ(0, pcap_init("/home/sll/pcap/pk/atp.pcap", 0));
	// 构造filter
	filter_t * expr = filter_new_or(filter_new_proto(17), filter_new_srcport(137));
	// 轮询
	ASSERT_EQ(0, pcap_poll(filter_pcap_date, expr, pcap_printf));
	EXPECT_EQ(0, pcap_end());
	filter_free(expr);
}


TEST(pcap_poll, poll8)
{
	EXPECT_EQ(0, pcap_init("/home/sll/pcap/pk/atp.pcap", 0));
	// 构造filter
	filter_t * expr = filter_new_not(filter_new_proto(17));
	// 轮询
	ASSERT_EQ(0, pcap_poll(filter_pcap_date, expr, pcap_printf));
	EXPECT_EQ(0, pcap_end());
	filter_free(expr);
}

TEST(next_pcap_cal, next_pcap_cal1)
{
	EXPECT_EQ(0, pcap_init("/home/sll/pcap/pk/atp.pcap", 1));
	// 构造filter
	filter_t * expr = filter_new_not(filter_new_proto(17));
	// 轮询
	ASSERT_EQ(0, next_pcap_cal(filter_pcap_date, expr, pcap_printf));
	EXPECT_EQ(0, pcap_end());
	filter_free(expr);
}


// 接口有问题，暂时这个测，后头再改


TEST(filter_new_or, new_or)
{
	// 构造filter
	filter_t * expr = filter_new_or(filter_new_proto(17), filter_new_proto(6));
	ASSERT_EQ(17, filter_get_data(filter_get_lhs(expr)));
	ASSERT_EQ(6, filter_get_data(filter_get_rhs(expr)));
	filter_free(expr);
}


TEST(filter_new_and, new_and)
{
	// 构造filter
	filter_t * expr = filter_new_and(filter_new_proto(17), filter_new_proto(6));
	ASSERT_EQ(17, filter_get_data(filter_get_lhs(expr)));
	ASSERT_EQ(6, filter_get_data(filter_get_rhs(expr)));
	filter_free(expr);
}

TEST(filter_new_not, new_not)
{
	// 构造filter
	filter_t * expr = filter_new_not(filter_new_proto(17));
	ASSERT_EQ(17, filter_get_data(filter_get_lhs(expr)));
	filter_free(expr);
}

TEST(filter_new_srcip, new_srcip)
{
	// 构造filter
	filter_t * expr = filter_new_srcip(111);
	ASSERT_EQ(111, filter_get_data(expr));
	filter_free(expr);
}

TEST(filter_new_dstip, new_dstip)
{
	// 构造filter
	filter_t * expr = filter_new_dstip(111);
	ASSERT_EQ(111, filter_get_data(expr));
	filter_free(expr);
}

TEST(filter_new_srcport, new_srcport)
{
	// 构造filter
	filter_t * expr = filter_new_srcport(111);
	ASSERT_EQ(111, filter_get_data(expr));
	filter_free(expr);
}


TEST(filter_new_dstport, new_dstport)
{
	// 构造filter
	filter_t * expr = filter_new_dstport(111);
	ASSERT_EQ(111, filter_get_data(expr));
	filter_free(expr);
}

TEST(filter_new_proto, new_proto)
{
	// 构造filter
	filter_t * expr = filter_new_proto(6);
	ASSERT_EQ(6, filter_get_data(expr));
	filter_free(expr);
}



