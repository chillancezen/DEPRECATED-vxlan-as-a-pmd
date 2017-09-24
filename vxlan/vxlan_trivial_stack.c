/*
Copyright (c) 2017 Jie Zheng
*/
#include "vxlan_trivial_stack.h"

#include <rte_prefetch.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_arp.h>
#include <rte_icmp.h>

void do_packet_selection_generic(struct vxlan_pmd_internal * internals,
		struct packet_set * raw_set,
		struct packet_set * arp_set,
		struct packet_set * icmp_set,
		struct packet_set * vxlan_set,
		struct packet_set * drop_set)
{
	int idx=0;
	struct rte_mbuf   * mbuf;
	struct ether_hdr  * ether_hdr;
	struct ipv4_hdr   * ip_hdr;
	struct udp_hdr    * udp_hdr;
	struct vxlan_hdr  * vxlan_hdr;
	
	for(idx=0;idx<raw_set->iptr;idx++){
		/*prefetch the next packet*/
		if((idx+1)<raw_set->iptr){
			rte_prefetch1(rte_pktmbuf_mtod(raw_set->set[idx+1],void*));
		}
		mbuf=raw_set->set[idx];
		/*vlan inspection*/
		if(internals->underlay_vlan){
			if((!(mbuf->ol_flags&PKT_RX_VLAN_STRIPPED))||
				(mbuf->vlan_tci!=internals->underlay_vlan))
				goto drop;
		}
		ether_hdr=rte_pktmbuf_mtod(mbuf,struct ether_hdr*);
		/*destination selection*/
		if(ether_hdr->ether_type==0x0008){
			ip_hdr=(struct ipv4_hdr*)(ether_hdr+1);
			if(ip_hdr->next_proto_id==0x11){
				udp_hdr=(struct udp_hdr*)((ip_hdr->version_ihl&0xf)*4+(uint8_t*)ip_hdr);
				if(ip_hdr->dst_addr!=internals->local_ip_as_be) goto drop;
				if(udp_hdr->dst_port!=VXLAN_UDP_PORT) goto drop;
				vxlan_hdr=(struct vxlan_hdr*)(udp_hdr+1);
				if(vxlan_hdr->vx_vni!=internals->vni) goto drop;
				rte_pktmbuf_adj(mbuf,30+(ip_hdr->version_ihl&0xf)*4);
				goto vxlan;
			}else if(ip_hdr->next_proto_id==1)
				goto icmp;
			else goto drop;
		}else if(ether_hdr->ether_type==0x0608){
			goto arp;
		}else
			goto drop;
		
		vxlan:
			push_packet_into_set(vxlan_set,mbuf);
			continue;
		icmp:
			push_packet_into_set(icmp_set,mbuf);
			continue;
		arp:
			push_packet_into_set(arp_set,mbuf);
			continue;
		drop:
			push_packet_into_set(drop_set,mbuf);
			continue;
	}
}

void arp_packet_process(struct vxlan_pmd_internal * internals,
			struct packet_set * arp_set,
			struct packet_set * drop_set)
{
	int idx=0;
	struct packet_set respond_set={
		.iptr=0,
	};
	struct rte_mbuf  * mbuf;
	struct ether_hdr * ether_hdr;
	struct arp_hdr   * arp_hdr;
	for(idx=0;idx<arp_set->iptr;idx++){
		mbuf=arp_set->set[idx];
		ether_hdr=rte_pktmbuf_mtod(mbuf,struct ether_hdr*);
		arp_hdr=(struct arp_hdr*)(ether_hdr+1);
		if(arp_hdr->arp_data.arp_tip!=internals->local_ip_as_be) goto drop;
		/*arp snooping to determine the remote endpoint's mac address*/
		{
			if(arp_hdr->arp_data.arp_sip==internals->remote_ip_as_be){
				rte_memcpy(internals->remote_mac,arp_hdr->arp_data.arp_sha.addr_bytes,6);
				internals->arp_initilized=1;
			}
		}
		/*generate arp response packet*/
		if(arp_hdr->arp_op==0x0100){
			arp_hdr->arp_op=0x0200;
			arp_hdr->arp_data.arp_tip=arp_hdr->arp_data.arp_sip;
			arp_hdr->arp_data.arp_sip=internals->local_ip_as_be;
			rte_memcpy(arp_hdr->arp_data.arp_tha.addr_bytes,arp_hdr->arp_data.arp_sha.addr_bytes,6);
			rte_memcpy(arp_hdr->arp_data.arp_sha.addr_bytes,internals->local_mac,6);
			rte_memcpy(ether_hdr->d_addr.addr_bytes,ether_hdr->s_addr.addr_bytes,6);
			rte_memcpy(ether_hdr->s_addr.addr_bytes,internals->local_mac,6);
			if(internals->underlay_vlan){
					mbuf->vlan_tci=internals->underlay_vlan;
					mbuf->ol_flags=PKT_TX_VLAN_PKT;
			}
		}else goto drop;
		
		push_packet_into_set(&respond_set,mbuf);
		continue;
		drop:
			push_packet_into_set(drop_set,mbuf);
			continue;
		
	}
	/*not safe to trasmit packets out*/
	if(respond_set.iptr){
		for(idx=0;idx<respond_set.iptr;idx++)
			vxlan_pmd_xmit_consume(internals,respond_set.set[idx]);
	}
}

void icmp_packet_process(struct vxlan_pmd_internal * internals,
			struct packet_set * icmp_set,
			struct packet_set * drop_set)
{
	
	int idx=0;
	struct packet_set respond_set={
		.iptr=0,
	};
	struct rte_mbuf  * mbuf;
	struct ether_hdr * ether_hdr;
	struct ipv4_hdr  * ip_hdr;
	struct icmp_hdr  * icmp_hdr;
	uint32_t csum=0;
	for(idx=0;idx<icmp_set->iptr;idx++){
		mbuf=icmp_set->set[idx];
		ether_hdr=rte_pktmbuf_mtod(mbuf,struct ether_hdr*);
		ip_hdr=(struct ipv4_hdr*)(ether_hdr+1);
		if(ip_hdr->dst_addr!=internals->local_ip_as_be) goto drop;
		icmp_hdr=(struct icmp_hdr *)((ip_hdr->version_ihl&0xf)*4+(uint8_t*)ip_hdr);
		if(icmp_hdr->icmp_type!=IP_ICMP_ECHO_REQUEST) goto drop;
		/*update icmp data */
		icmp_hdr->icmp_type=IP_ICMP_ECHO_REPLY;
		csum=(~(icmp_hdr->icmp_cksum))&0xffff;
		csum+=0xfff7;
		while(csum>>16)
			csum=(csum&0xffff)+(csum>>16);
		icmp_hdr->icmp_cksum=(~csum)&0xffff;
		/*update ip data*/
		ip_hdr->dst_addr=ip_hdr->src_addr;
		ip_hdr->src_addr=internals->local_ip_as_be;
		ip_hdr->time_to_live=64;
		ip_hdr->hdr_checksum=0;
		mbuf->l2_len=sizeof(struct ether_hdr);
		mbuf->l3_len=(ip_hdr->version_ihl&0xf)<<2;
		mbuf->ol_flags=PKT_TX_IPV4|PKT_TX_IP_CKSUM;
		if(internals->underlay_vlan){
			mbuf->vlan_tci=internals->underlay_vlan;
			mbuf->ol_flags|=PKT_TX_VLAN_PKT;
		}
		rte_memcpy(ether_hdr->d_addr.addr_bytes,
					ether_hdr->s_addr.addr_bytes,
					6);
		rte_memcpy(ether_hdr->s_addr.addr_bytes,
					internals->local_mac,
					6);
		push_packet_into_set(&respond_set,mbuf);
		continue;
		drop:
			push_packet_into_set(drop_set,mbuf);
			continue;
	}
	if(respond_set.iptr){
		for(idx=0;idx<respond_set.iptr;idx++)
			vxlan_pmd_xmit_consume(internals,respond_set.set[idx]);
	}
}

void vxlan_packet_process(struct vxlan_pmd_internal* internals __rte_unused,
			struct packet_set * vxlan_set,/*since we know mbufs can accommodate all the pkts in vxlan_set*/
			struct rte_mbuf ** mbufs)
{
	int idx=0;
	for(idx=0;idx<vxlan_set->iptr;idx++)
		mbufs[idx]=vxlan_set->set[idx];
}

void drop_packet_process(struct vxlan_pmd_internal * internals __rte_unused,
			struct packet_set * drop_set)
{
	int idx=0;
	for(idx=0;idx<drop_set->iptr;idx++){
		rte_pktmbuf_free(drop_set->set[idx]);
	}
}

void post_rx_process(struct vxlan_pmd_internal* internals)
{
	uint64_t cur_tsc;
	uint64_t diff_tsc;
	int rc=0;
	int idx=0;
	if(!internals->xmit_pending_index)
		return ;

	
	if(rte_spinlock_trylock(&internals->xmit_guard)){
		rc=rte_eth_tx_burst(internals->underlay_port,
					0,
					internals->mbufs_pending,
					internals->xmit_pending_index);
		for(idx=rc;idx<internals->xmit_pending_index;idx++)
			rte_pktmbuf_free(internals->mbufs_pending[idx]);
		internals->xmit_pending_index=0;
		rte_spinlock_unlock(&internals->xmit_guard);
	}else{
		cur_tsc=rte_rdtsc();
		diff_tsc=cur_tsc-internals->tsc_1st_try;
		if(unlikely(diff_tsc>(internals->cpu_HZ*XMIT_PENDING_SECONDS))){
			for(idx=0;idx<internals->xmit_pending_index;idx++)
				rte_pktmbuf_free(internals->mbufs_pending[idx]);
			internals->xmit_pending_index=0;
		}
	}
}
void generate_arp_request(struct vxlan_pmd_internal * internals,
			struct rte_mbuf   * mbuf)
{
	struct ether_hdr * ether_hdr;
	struct arp_hdr   * arp_hdr;
	rte_pktmbuf_reset(mbuf);
	rte_pktmbuf_append(mbuf,64);

	ether_hdr=rte_pktmbuf_mtod(mbuf,struct ether_hdr*);
	memset(ether_hdr,0x0,64);
	rte_memcpy(ether_hdr->d_addr.addr_bytes,
				"\xff\xff\xff\xff\xff\xff",6);
	rte_memcpy(ether_hdr->s_addr.addr_bytes,
				internals->local_mac,6);
	ether_hdr->ether_type=0x0608;
	arp_hdr=(struct arp_hdr*)(ether_hdr+1);
	arp_hdr->arp_hrd=0x0100;
	arp_hdr->arp_pro=0x0008;
	arp_hdr->arp_hln=0x06;
	arp_hdr->arp_pln=0x04;
	arp_hdr->arp_op=0x0100;

	arp_hdr->arp_data.arp_sip=internals->local_ip_as_be;
	arp_hdr->arp_data.arp_tip=internals->remote_ip_as_be;
	rte_memcpy(arp_hdr->arp_data.arp_sha.addr_bytes,
				internals->local_mac,6);
	rte_memcpy(arp_hdr->arp_data.arp_tha.addr_bytes,
				"\x00\x00\x00\x00\x00\x00",6);
	if(internals->underlay_vlan){
		mbuf->vlan_tci=internals->underlay_vlan;
		mbuf->ol_flags=PKT_TX_VLAN_PKT;
	}
}
void vxlan_encapsulate(struct vxlan_pmd_internal * internals,
				struct rte_mbuf ** mbufs,
				int nr_mbuf)
{

	int idx=0;
	struct ether_hdr  * ether_hdr;
	struct ipv4_hdr   * ip_hdr;
	struct udp_hdr    * udp_hdr;
	struct vxlan_hdr  * vxlan_hdr;
	for(idx=0;idx<nr_mbuf;idx++){
		rte_pktmbuf_prepend(mbufs[idx],50);//it's supposed to be always successful
		ether_hdr=rte_pktmbuf_mtod(mbufs[idx],struct ether_hdr*);

		/*fill ethernet data*/
		rte_memcpy(ether_hdr->d_addr.addr_bytes,internals->remote_mac,6);
		rte_memcpy(ether_hdr->s_addr.addr_bytes,internals->local_mac,6);
		ether_hdr->ether_type=0x0008;

		/*fill IP layer data*/
		ip_hdr=(struct ipv4_hdr*)(ether_hdr+1);
		ip_hdr->version_ihl=0x45;
		ip_hdr->type_of_service=0x0;
		ip_hdr->total_length=mbufs[idx]->pkt_len-14;
		ip_hdr->total_length=SWAP_ORDER16(ip_hdr->total_length);
		ip_hdr->packet_id=internals->ip_identity++;
		ip_hdr->packet_id=SWAP_ORDER16(ip_hdr->packet_id);
		ip_hdr->fragment_offset=0x0040;
		ip_hdr->time_to_live=0x40;
		ip_hdr->next_proto_id=0x11;
		ip_hdr->hdr_checksum=0x0;
		ip_hdr->src_addr=internals->local_ip_as_be;
		ip_hdr->dst_addr=internals->remote_ip_as_be;

		udp_hdr=(struct udp_hdr*)(ip_hdr+1);
		udp_hdr->dgram_cksum=0;
		udp_hdr->dgram_len=mbufs[idx]->pkt_len-34;
		udp_hdr->dgram_len=SWAP_ORDER16(udp_hdr->dgram_len);
		udp_hdr->dst_port=VXLAN_UDP_PORT;
		udp_hdr->src_port=VXLAN_UDP_PORT;/*to-do:distribute src port more evenly*/

		vxlan_hdr=(struct vxlan_hdr *)(udp_hdr+1);
		vxlan_hdr->vx_flags=0x0008;
		vxlan_hdr->vx_vni=internals->vni;
		
		mbufs[idx]->l2_len=14;
		mbufs[idx]->l3_len=20;
		mbufs[idx]->ol_flags=PKT_TX_IP_CKSUM|PKT_TX_IPV4;

		if(internals->underlay_vlan){
			mbufs[idx]->vlan_tci=internals->underlay_vlan;
			mbufs[idx]->ol_flags|=PKT_TX_VLAN_PKT;
		}
		
	}
}
