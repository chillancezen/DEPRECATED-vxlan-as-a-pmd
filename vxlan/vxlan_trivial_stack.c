/*
Copyright (c) 2017 Jie Zheng
*/
#include "vxlan_trivial_stack.h"

#include <rte_prefetch.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_arp.h>
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
	int rc;
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
		rc=rte_eth_tx_burst(internals->underlay_port,0,respond_set.set,respond_set.iptr);
		for(idx=rc;idx<respond_set.iptr;idx++)
			push_packet_into_set(drop_set,respond_set.set[idx]);
	}
}

void icmp_packet_process(struct vxlan_pmd_internal * internals,
			struct packet_set * icmp_set,
			struct packet_set * drop_set)
{

}

