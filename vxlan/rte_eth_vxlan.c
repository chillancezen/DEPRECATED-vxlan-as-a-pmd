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
#define VXLAN_PMD_MEMPOOL_NR (1024*8)
#define VXLAN_PMD_MEMPOOL_CACHE_SIZE 256

#define VXLAN_PMD_ARG_UNDERLAY_DEV "underlay_dev"
#define VXLAN_PMD_ARG_LOCAL_IP "local_ip"
#define VXLAN_PMD_ARG_REMOTE_IP "remote_ip"
#define VXLAN_PMD_ARG_UNDERLAY_VLAN "underlay_vlan" /*optional,default is 0*/

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
int vxlan_pmd_probe(struct rte_vdev_device *dev)
{
	int rc;
	const char * params=rte_vdev_device_args(dev);
	const char * dev_name=rte_vdev_device_name(dev);
	char underlay_dev_params[128];
	uint32_t remote_ip=0; /*all in big endian*/
	uint32_t local_ip=0;
	uint16_t underlay_vlan=0;
	struct rte_kvargs * kvlist=NULL;
	uint8_t underlay_port=-1;
	
	struct rte_eth_dev_info dev_info;
	struct rte_eth_conf     port_conf;
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
		VXLAN_PMD_LOG("INVALID ARGUMENTS FOR VXLAN PMD\n");
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
		VXLAN_PMD_LOG("CAN NOT ATTACH PORT WITH ARG:%s\n",underlay_dev_params);
		return -4;
	}
	VXLAN_PMD_LOG("ATTACH %s AS PORT %d\n",underlay_dev_params,underlay_port);
	/*2 NIC offload capability check */
	rte_eth_dev_info_get(underlay_port, &dev_info);
	if(!(dev_info.rx_offload_capa&DEV_TX_OFFLOAD_IPV4_CKSUM)){
		VXLAN_PMD_LOG("underlay port %d does not support DEV_TX_OFFLOAD_IPV4_CKSUM nic offload\n",underlay_port);
		goto error_dev_detach;
	}
	if(!(dev_info.rx_offload_capa&DEV_RX_OFFLOAD_VLAN_STRIP)){
		VXLAN_PMD_LOG("underlay port %d does not support DEV_RX_OFFLOAD_VLAN_STRIP nic offload\n",underlay_port);
		goto error_dev_detach;
	}
	if(!(dev_info.rx_offload_capa&DEV_TX_OFFLOAD_VLAN_INSERT)){
		VXLAN_PMD_LOG("underlay port %d does not support DEV_TX_OFFLOAD_VLAN_INSERT nic offload\n",underlay_port);
		goto error_dev_detach;
	}
	/*3 configure the underlay port right now*/
	memset(&port_conf,0x0,sizeof(struct rte_eth_conf));
	port_conf.rxmode.mq_mode=ETH_MQ_RX_NONE;
	port_conf.rxmode.max_rx_pkt_len=ETHER_MAX_LEN;
	port_conf.rxmode.hw_ip_checksum=1;
	port_conf.rxmode.hw_vlan_strip=1;
	rc=rte_eth_dev_configure(underlay_port,1,1,&port_conf);
	if(rc<0){
		VXLAN_PMD_LOG("can not configure port %d\n",underlay_port);
		goto error_dev_detach;
	}
	
	
	return 0;

	error_dev_detach:
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
int vxlan_pmd_remove(struct rte_vdev_device *dev)
{
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

