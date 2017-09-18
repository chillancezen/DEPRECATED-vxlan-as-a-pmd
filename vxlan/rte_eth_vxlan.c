/*
Copyright (c) 2017 Jie Zheng
*/
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ethdev_vdev.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_vdev.h>
#include <rte_kvargs.h>
#include <rte_spinlock.h>
#include <rte_cycles.h>
#include <rte_mempool.h>


#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
	struct ether_addr pmd_mac;
	uint32_t local_ip_as_be;
	uint32_t remote_ip_as_be;
};
#define DEFAULT_RX_DESCRIPTORS 1024
#define DEFAULT_TX_DESCRIPTORS 1024
#define VXLAN_PMD_MEMPOOL_NR (1024*8)
#define VXLAN_PMD_MEMPOOL_CACHE_SIZE 256

#define VXLAN_PMD_ARG_UNDERLAY_DEV "underlay_dev"
#define VXLAN_PMD_ARG_LOCAL_IP "local_ip"
#define VXLAN_PMD_ARG_REMOTE_IP "remote_ip"
#define VXLAN_PMD_ARG_UNDERLAY_VLAN "underlay_vlan" /*optional,default is 0*/
static uint16_t pmd_mac_counter=0x1;
/*here for security reason, we do not create per-device mempool
since it's possible when the packet from mempool is being processed while the device is releasing
which may involves releasing its relavant mempool,thus leading errors maybe*/
struct rte_mempool * g_vxlan_pmd_pktpool=NULL;


static const char * valid_arguments[]={
	VXLAN_PMD_ARG_UNDERLAY_VLAN,
	VXLAN_PMD_ARG_UNDERLAY_DEV,
	VXLAN_PMD_ARG_LOCAL_IP,
	VXLAN_PMD_ARG_REMOTE_IP,
	NULL,
};

static struct rte_eth_link vxlan_pmd_link = {
	.link_speed = ETH_SPEED_NUM_10G,
	.link_duplex = ETH_LINK_FULL_DUPLEX,
	.link_status = ETH_LINK_UP,
	.link_autoneg = ETH_LINK_SPEED_AUTONEG,
};

static int argument_callback_for_underlay_vdev(const char * key __rte_unused,
			const char * value,
			void * extra
	)
{
	strcpy(extra,value);
	return 0;
}
static int argument_callback_for_ip(const char * key __rte_unused,
			const char * value,
			void * extra)
{
	in_addr_t addr=inet_addr(value);
	*(uint32_t*)extra=((uint32_t)addr);
	return 0;
}
static int argument_callback_for_underlay_vlan(const char * key __rte_unused,
			const char * value,
			void * extra)
{
	*(uint16_t*)extra=(uint16_t)atoi(value);
	return 0;
}
static int vxlan_pmd_probe(struct rte_vdev_device *dev)
{
	int rc;
	const char * params=rte_vdev_device_args(dev);
	
	char underlay_dev_params[128];
	uint32_t remote_ip=0; /*all in big endian*/
	uint32_t local_ip=0;
	uint16_t underlay_vlan=0;
	struct rte_kvargs * kvlist=NULL;
	uint8_t underlay_port=-1;
	
	struct rte_eth_dev_info dev_info;
	struct rte_eth_conf     port_conf;
	struct rte_eth_dev *    eth_dev;
	struct rte_eth_dev_data * eth_dev_data;
	struct vxlan_pmd_internal * internals;
	memset(underlay_dev_params,0x0,sizeof(underlay_dev_params));
	
	kvlist=rte_kvargs_parse(params,valid_arguments);
	if(!kvlist)
		return -2;
	rte_kvargs_process(kvlist,
			VXLAN_PMD_ARG_UNDERLAY_DEV,
			argument_callback_for_underlay_vdev,
			underlay_dev_params);
	rte_kvargs_process(kvlist,
			VXLAN_PMD_ARG_REMOTE_IP,
			argument_callback_for_ip,
			&remote_ip);
	rte_kvargs_process(kvlist,
			VXLAN_PMD_ARG_LOCAL_IP,
			argument_callback_for_ip,
			&local_ip);
	rte_kvargs_process(kvlist,
			VXLAN_PMD_ARG_UNDERLAY_VLAN,
			argument_callback_for_underlay_vlan,
			&underlay_vlan);
	rte_kvargs_free(kvlist);
	if(!underlay_dev_params[0]||!remote_ip||!local_ip){
		VXLAN_PMD_LOG("invalid argument for vxlan pmd device\n");
		return -3;
	}
	/*0 preserver mempool for underlay device*/
	if(!g_vxlan_pmd_pktpool)
		g_vxlan_pmd_pktpool=rte_pktmbuf_pool_create("vxlan_pmd_pktpool",
									VXLAN_PMD_MEMPOOL_NR,
									VXLAN_PMD_MEMPOOL_CACHE_SIZE,
									0,
									RTE_MBUF_DEFAULT_BUF_SIZE,
									SOCKET_ID_ANY);
	if(!g_vxlan_pmd_pktpool){
		VXLAN_PMD_LOG("can not perserve pkt pool for vxlan pmd\n");
		return -4;
	}
	/*1 register the underlay dev*/
	rc=rte_eth_dev_attach(underlay_dev_params,&underlay_port);
	if(rc){
		VXLAN_PMD_LOG("can not attach underlay port with arg:%s\n",underlay_dev_params);
		return -4;
	}
	VXLAN_PMD_LOG("attach %s as underlay port %d\n",underlay_dev_params,underlay_port);
	/*2 NIC offload capability check */
	rte_eth_dev_info_get(underlay_port, &dev_info);
	if(!(dev_info.rx_offload_capa&DEV_TX_OFFLOAD_IPV4_CKSUM)){
		VXLAN_PMD_LOG("underlay port %d does not support DEV_TX_OFFLOAD_IPV4_CKSUM nic offload\n",underlay_port);
		goto error_underlay_dev_detach;
	}
	if(!(dev_info.rx_offload_capa&DEV_RX_OFFLOAD_VLAN_STRIP)){
		VXLAN_PMD_LOG("underlay port %d does not support DEV_RX_OFFLOAD_VLAN_STRIP nic offload\n",underlay_port);
		goto error_underlay_dev_detach;
	}
	if(!(dev_info.rx_offload_capa&DEV_TX_OFFLOAD_VLAN_INSERT)){
		VXLAN_PMD_LOG("underlay port %d does not support DEV_TX_OFFLOAD_VLAN_INSERT nic offload\n",underlay_port);
		goto error_underlay_dev_detach;
	}
	/*3 configure the underlay port right now*/
	memset(&port_conf,0x0,sizeof(struct rte_eth_conf));
	port_conf.rxmode.mq_mode=ETH_MQ_RX_NONE;
	port_conf.rxmode.max_rx_pkt_len=ETHER_MAX_LEN;
	port_conf.rxmode.hw_ip_checksum=1;
	port_conf.rxmode.hw_vlan_strip=1;
	rc=rte_eth_dev_configure(underlay_port,1,1,&port_conf);
	if(rc<0){
		VXLAN_PMD_LOG("can not configure underlay port %d\n",underlay_port);
		goto error_underlay_dev_detach;
	}
	/*4.setup rx&tx queue for underlay port*/
	rc=rte_eth_rx_queue_setup(underlay_port,
				0,
				DEFAULT_RX_DESCRIPTORS,
				SOCKET_ID_ANY,
				NULL,
				g_vxlan_pmd_pktpool);
	if(rc<0){
		VXLAN_PMD_LOG("can not setup rx queue for underlay port %d\n",underlay_port);
		goto error_underlay_dev_detach;
	}
	rte_eth_dev_info_get(underlay_port,&dev_info);
	dev_info.default_txconf.txq_flags=0;
	rc=rte_eth_tx_queue_setup(underlay_port,
				0,
				DEFAULT_TX_DESCRIPTORS,
				SOCKET_ID_ANY,
				&dev_info.default_txconf);
	if(rc<0){
		VXLAN_PMD_LOG("can not setup tx queue for underlay port %d\n",underlay_port);
		goto error_underlay_dev_detach;
	}
	
	/*5.register overlay device*/
	eth_dev_data=rte_zmalloc(NULL,sizeof(struct rte_eth_dev_data),64);
	if(!eth_dev_data){
		VXLAN_PMD_LOG("can not allocate rte_eth_dev_data for overlay device\n");
		goto error_underlay_dev_detach;
	}
	
	eth_dev=rte_eth_vdev_allocate(dev,sizeof(struct vxlan_pmd_internal));
	if(!eth_dev){
		VXLAN_PMD_LOG("can not allocate rte_eth_dev for overlay device\n");
		goto error_release_overlay_dev_data;
	}
	
	rte_memcpy(eth_dev_data,eth_dev->data,sizeof(struct rte_eth_dev_data));
	internals=(struct vxlan_pmd_internal*)eth_dev->data->dev_private;
	internals->underlay_port=underlay_port;
	internals->remote_ip_as_be=remote_ip;
	internals->local_ip_as_be=local_ip;
	rte_eth_macaddr_get(underlay_port,&internals->pmd_mac);
	rte_memcpy(internals->local_mac,internals->pmd_mac.addr_bytes,6);
	/*to generate virtual pmd's mac address,we extract 2nd ,3rd byte of the 
	underlay port's mac,and construct a word,then add by a counter*/
	{
		uint16_t * _tmp_ptr=(uint16_t *)(internals->pmd_mac.addr_bytes+2);
		*_tmp_ptr+=pmd_mac_counter++;
	}
	eth_dev_data->nb_rx_queues=1;
	eth_dev_data->nb_tx_queues=1;
	eth_dev_data->dev_link=vxlan_pmd_link;
	eth_dev_data->mac_addrs=&internals->pmd_mac;
	eth_dev_data->dev_flags=RTE_ETH_DEV_DETACHABLE;
	eth_dev->data=eth_dev_data;

	VXLAN_PMD_LOG("underlay port %d: %02x:%02x:%02x:%02x:%02x:%02x\n",underlay_port,
		internals->local_mac[0],
		internals->local_mac[1],
		internals->local_mac[2],
		internals->local_mac[3],
		internals->local_mac[4],
		internals->local_mac[5]);
	VXLAN_PMD_LOG("overlay port %d: %02x:%02x:%02x:%02x:%02x:%02x\n",eth_dev->data->port_id,
		internals->pmd_mac.addr_bytes[0],
		internals->pmd_mac.addr_bytes[1],
		internals->pmd_mac.addr_bytes[2],
		internals->pmd_mac.addr_bytes[3],
		internals->pmd_mac.addr_bytes[4],
		internals->pmd_mac.addr_bytes[5]);
	
	
	return 0;
	error_release_overlay_dev_data:
		if(eth_dev_data)
			rte_free(eth_dev_data);
	error_underlay_dev_detach:
		{
			int release_rc;
			char dev_name[128];
			rte_eth_dev_stop(underlay_port);
			rte_eth_dev_close(underlay_port);
			release_rc=rte_eth_dev_detach(underlay_port,dev_name);
			if(release_rc)
				VXLAN_PMD_LOG("error occurs during releasing %s \n",dev_name);
		}
		return -1;
}
static int vxlan_pmd_remove(struct rte_vdev_device *dev)
{
	struct rte_eth_dev * eth_dev=NULL;
	if(!dev)
		return -1;
	eth_dev=rte_eth_dev_allocated(rte_vdev_device_name(dev));
	if(!eth_dev)
		return -2;
	rte_free(eth_dev->data->dev_private);
	rte_free(eth_dev->data);
	rte_eth_dev_release_port(eth_dev);
	return 0;
}
static struct rte_vdev_driver vxlan_pmd_driver={
	.probe=vxlan_pmd_probe,
	.remove=vxlan_pmd_remove,
};
RTE_PMD_REGISTER_VDEV(net_vxlan,vxlan_pmd_driver);
RTE_PMD_REGISTER_ALIAS(net_vxlan,eth_vxlan);
RTE_PMD_REGISTER_PARAM_STRING(net_vxlan,
	VXLAN_PMD_ARG_UNDERLAY_DEV "=<pci-bus-addr>"
	VXLAN_PMD_ARG_LOCAL_IP "=<ip-addr> "
	VXLAN_PMD_ARG_REMOTE_IP "=<ip-addr> "
	VXLAN_PMD_ARG_UNDERLAY_VLAN "=<vlan-id>");

