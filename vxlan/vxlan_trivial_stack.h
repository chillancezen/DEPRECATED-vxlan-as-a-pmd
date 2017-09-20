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

struct vxlan_pmd_internal{
	uint8_t underlay_port;
	uint8_t local_mac[6];
	uint8_t remote_mac[6];
	uint16_t underlay_vlan;
	struct ether_addr pmd_mac;
	uint32_t local_ip_as_be;
	uint32_t remote_ip_as_be;
};


#define MAX_PACKETS_IN_SET 64
#define VXLAN_PMD_MIN(a,b) (((a)<(b))?(a):(b))

struct packet_set{
	int iptr;
	struct rte_mbuf * set[MAX_PACKETS_IN_SET];
};

#define reset_packet_set(set_ptr) {\
	(set_ptr)->iptr=0; \
}
#define count_packet_set(set_ptr) ((set_ptr)->iptr)

#define push_packet_into_set(set_ptr,mbuf) {\
	(set_ptr)->set[(set_ptr)->iptr]=(mbuf);\
	(set_ptr)->iptr++; \
}

void do_packet_selection_common(struct vxlan_pmd_internal * internals,
		struct packet_set * raw_set,
		struct packet_set * arp_set,
		struct packet_set * icmp_set,
		struct packet_set * vxlan_set,
		struct packet_set * drop_set,
		void * extra);


#endif
