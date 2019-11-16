#include "filter.h"



typedef int (*match_fun)(const pcap_packet_info *pkinfo, const filter_t *expr);

/**
 * @brief 过滤表达式树（二叉树）
 */
typedef struct filter_t {
	match_fun op;                           //该类操作的回调钩子集合
	void *data;                             //表达式额外数据，比如端口匹配用到的端口值
	filter_t *lhs;                          //左子树
	filter_t *rhs;                          //右子树
} filter_t;

/*---------------------------------------------------------------------------------*\
 *  match函数的实现
\*---------------------------------------------------------------------------------*/
#define FILTER_MATCH        1
#define FILTER_UNMATCH      0

static int match_expr(const pcap_packet_info *pkinfo, const filter_t *expr)
{
	assert(pkinfo);
	assert(expr);
	assert(expr->op);
	//printf("match_expr\n");
	return expr->op(pkinfo, expr);
}


int match_and(const pcap_packet_info *pkinfo, const filter_t *expr)
{
	assert(pkinfo);
	assert(expr);
	assert(expr->lhs);
	assert(expr->rhs);

	int ret = match_expr(pkinfo, expr->lhs);
	if (ret == FILTER_MATCH)
		ret = match_expr(pkinfo, expr->rhs);
	return ret;
}

int match_or(const pcap_packet_info *pkinfo, const filter_t *expr)
{
	assert(pkinfo);
	assert(expr);
	assert(expr->lhs);
	assert(expr->rhs);

	int ret = match_expr(pkinfo, expr->lhs);
	if (ret == FILTER_UNMATCH)
		ret = match_expr(pkinfo, expr->rhs);
	return ret;
}

int match_not(const pcap_packet_info *pkinfo, const filter_t *expr)
{
	assert(pkinfo);
	assert(expr);
	assert(expr->lhs);

	int ret = match_expr(pkinfo, expr->lhs);
	if (ret == FILTER_MATCH)
		return FILTER_UNMATCH;
	return FILTER_MATCH;
}

int match_srcip(const pcap_packet_info *pkinfo, const filter_t *expr)
{
	assert(pkinfo);
	assert(expr);
	assert(expr->data);
	//printf("expr->data=%u, pkinfo->srcip=%u\n", *((int*)(expr->data)), pkinfo->srcip);
	if (*((int*)(expr->data)) == pkinfo->srcip)
		return FILTER_MATCH;
	return FILTER_UNMATCH;
}


int match_dstip(const pcap_packet_info *pkinfo, const filter_t *expr)
{
	assert(pkinfo);
	assert(expr);
	assert(expr->data);
	//printf("expr->data=%u, pkinfo->dstip=%u\n", *((int*)(expr->data)), pkinfo->dstip);
	if (*((int*)(expr->data)) == pkinfo->dstip)
		return FILTER_MATCH;
	return FILTER_UNMATCH;
}


int match_srcport(const pcap_packet_info *pkinfo, const filter_t *expr)
{
	assert(pkinfo);
	assert(expr);
	assert(expr->data);
	//printf("expr->data=%d, pkinfo->srcport=%d\n", *((int*)(expr->data)), pkinfo->srcport);
	if (*((int*)(expr->data)) == pkinfo->srcport)
		return FILTER_MATCH;
	return FILTER_UNMATCH;
}

int match_dstport(const pcap_packet_info *pkinfo, const filter_t *expr)
{
	assert(pkinfo);
	assert(expr);
	assert(expr->data);

	//printf("expr->data=%d, pkinfo->dstport=%d\n", *((int*)(expr->data)), pkinfo->dstport);

	if (*((int*)(expr->data)) == pkinfo->dstport)
		return FILTER_MATCH;
	return FILTER_UNMATCH;
}


int match_proto(const pcap_packet_info *pkinfo, const filter_t *expr)
{
	assert(pkinfo);
	assert(expr);
	assert(expr->data);
	//printf("expr->data=%d, pkinfo->proto=%d\n", *((int*)(expr->data)), pkinfo->proto);
	if (*((int*)(expr->data)) == pkinfo->proto)
		return FILTER_MATCH;
	return FILTER_UNMATCH;
}


filter_t *filter_new_srcip(unsigned int srcip)
{
	filter_t *expr = (filter_t *)alloc_fun(sizeof(filter_t));
	expr->data = alloc_fun(sizeof(int));
	*(int*)expr->data = srcip;
	expr->op = match_srcip;
	return expr;
}

filter_t *filter_new_dstip(unsigned int dstip)
{
	filter_t *expr = (filter_t *)alloc_fun(sizeof(filter_t));
	expr->data = alloc_fun(sizeof(int));
	*(int*)expr->data = dstip;
	expr->op = match_dstip;
	return expr;
}


filter_t *filter_new_srcport(int srcport)
{
	filter_t *expr = (filter_t *)alloc_fun(sizeof(filter_t));
	expr->data = alloc_fun(sizeof(int));
	*(int*)expr->data = srcport;
	expr->op = match_srcport;
	return expr;
}

filter_t *filter_new_dstport(int dstport)
{
	filter_t *expr = (filter_t *)alloc_fun(sizeof(filter_t));
	expr->data = alloc_fun(sizeof(int));
	*(int*)expr->data = dstport;
	expr->op = match_dstport;
	return expr;
}

filter_t *filter_new_proto(int proto)
{
	filter_t *expr = (filter_t *)alloc_fun(sizeof(filter_t));
	expr->data = alloc_fun(sizeof(int));
	*(int*)expr->data = proto;
	expr->op = match_proto;
	return expr;
}

filter_t *filter_new_and(filter_t *lhs, filter_t *rhs)
{
	assert(lhs);
	assert(rhs);
	filter_t *expr = (filter_t *)alloc_fun(sizeof(filter_t));
	expr->lhs = lhs;
	expr->rhs = rhs;
	expr->op = match_and;
	return expr;
}

filter_t *filter_new_or(filter_t *lhs, filter_t *rhs)
{
	assert(lhs);
	assert(rhs);
	filter_t *expr = (filter_t *)alloc_fun(sizeof(filter_t));
	expr->lhs = lhs;
	expr->rhs = rhs;
	expr->op = match_or;
	return expr;
}

filter_t *filter_new_not(filter_t *lhs)
{
	assert(lhs);
	filter_t *expr = (filter_t *)alloc_fun(sizeof(filter_t));
	expr->lhs = lhs;
	expr->op = match_not;
	return expr;
}

//用于gtest
int filter_get_data(filter_t *expr)
{
	assert(expr);
	
	return *(int*)expr->data;
}

filter_t *filter_get_lhs(filter_t *expr)
{
	assert(expr);
	
	return expr->lhs;
}

filter_t *filter_get_rhs(filter_t *expr)
{
	assert(expr);
	
	return expr->rhs;
}



int filter_free(filter_t *expr)
{
	assert(expr);
	if (expr->lhs)
		filter_free(expr->lhs);
	if (expr->rhs)
		filter_free(expr->rhs);
	free(expr->data);
	return 0;
}


int filter_pcap_date(pcap_packet_info *pk_info, void *udata)
{
	assert(pk_info);
	assert(udata);
	
	return match_expr(pk_info, (filter_t*)udata);
}


