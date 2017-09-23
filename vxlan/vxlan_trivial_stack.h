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


#define VNI_SWAP_ORDER(vni) (((((uint32_t)(vni))>>16)&0xff)| \
	(((uint32_t)(vni))&0xff00)| \
	((((uint32_t)(vni))<<16)&0xff0000))

#define SWAP_ORDER16(val) ((((val)<<8)&0xff00)|(((val)>>8)&0x00ff))


struct vxlan_pmd_internal{
	uint8_t arp_initilized;
	uint8_t underlay_port;
	uint8_t local_mac[6];
	uint8_t remote_mac[6];
	struct ether_addr pmd_mac;
	uint16_t underlay_vlan;
	uint16_t ip_identity;
	uint32_t local_ip_as_be;
	uint32_t remote_ip_as_be;
	uint32_t vni;

	uint64_t last_arp_sent; /*arp suppresion*/
	uint64_t cpu_HZ;
};

#define VXLAN_UDP_PORT 0xb512 
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

void do_packet_selection_generic(struct vxlan_pmd_internal * internals,
		struct packet_set * raw_set,
		struct packet_set * arp_set,
		struct packet_set * icmp_set,
		struct packet_set * vxlan_set,
		struct packet_set * drop_set);

void arp_packet_process(struct vxlan_pmd_internal * internals,
			struct packet_set * arp_set,
			struct packet_set * drop_set);

void icmp_packet_process(struct vxlan_pmd_internal * internals,
			struct packet_set * icmp_set,
			struct packet_set * drop_set);

void vxlan_packet_process(struct vxlan_pmd_internal* internals,
			struct packet_set * vxlan_set,
			struct rte_mbuf ** mbufs);

void drop_packet_process(struct vxlan_pmd_internal * internals,
			struct packet_set * drop_set);

void generate_arp_request(struct vxlan_pmd_internal * internals,
			struct rte_mbuf   * mbuf);

void vxlan_encapsulate(struct vxlan_pmd_internal * internals,
				struct rte_mbuf ** mbufs,
				int nr_mbuf);


#endif
