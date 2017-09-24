/*
Copyright (c) 2017 Jie Zheng
*/
#ifndef _VXLAN_TRIVIAL_STACK
#define _VXLAN_TRIVIAL_STACK
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_spinlock.h>
#include <rte_cycles.h>
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
#define VXLAN_UDP_PORT 0xb512 
#define MAX_PACKETS_IN_SET 64
#define MAX_PACKETS_IN_PENDING_XMIT_BUF 32
#define XMIT_PENDING_SECONDS 2

struct vxlan_pmd_internal{
	uint8_t arp_initilized:1;
	uint8_t xmit_pending_index;
	uint8_t underlay_port;
	uint8_t local_mac[6];
	uint8_t remote_mac[6];
	
	uint16_t underlay_vlan;
	uint16_t ip_identity;
	uint32_t local_ip_as_be;
	uint32_t remote_ip_as_be;
	uint32_t vni;

	uint64_t last_arp_sent; /*tsc arp suppresion*/
	uint64_t cpu_HZ;
	uint64_t tsc_1st_try;
	rte_spinlock_t xmit_guard;
	
	
	__attribute__((aligned(64)))
		struct ether_addr pmd_mac;
		uint64_t rx_pkts;
		uint64_t tx_pkts;
		uint64_t rx_bytes;
		uint64_t tx_bytes;
	__attribute__((aligned(64)))
		struct rte_mbuf *mbufs_pending[MAX_PACKETS_IN_PENDING_XMIT_BUF];
};

/*
*put a mbuf into the pending buffer to xmit,
*if there is no room, the packet will be freeed.
*/
static __attribute__((always_inline)) inline 
	void vxlan_pmd_xmit_consume(struct vxlan_pmd_internal * internals,
				struct rte_mbuf * mbuf)
{
	if(internals->xmit_pending_index>=MAX_PACKETS_IN_PENDING_XMIT_BUF){
		rte_pktmbuf_free(mbuf);
		return;
	}
	if(!internals->xmit_pending_index)
		internals->tsc_1st_try=rte_rdtsc();
	internals->mbufs_pending[internals->xmit_pending_index]=mbuf;
	internals->xmit_pending_index++;
}


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
void post_rx_process(struct vxlan_pmd_internal* internals);


#endif
