/*
Copyright (c) 2017 Jie Zheng
*/
#ifndef _VXLAN_TRIVIAL_STACK
#define _VXLAN_TRIVIAL_STACK
#include <rte_mbuf.h>
#include <rte_ethdev.h>

#define VXLAN_DEBUG

#if defined(VXLAN_DEBUG)
	#define VXLAN_PMD_LOG(format,...) \
		printf("[VXLAN_PMD]: "format,##__VA_ARGS__)
#else
	#define VXLAN_PMD_LOG(format,...)
#endif


#endif
