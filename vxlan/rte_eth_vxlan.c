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

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#define VXLAN_PMD_ARG_UNDERLAY_DEV "underlay_dev"
#define VXLAN_PMD_ARG_LOCAL_IP "local_ip"
#define VXLAN_PMD_ARG_REMOTE_IP "remote_ip"



static const char * valid_arguments[]={
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
int vxlan_pmd_probe(struct rte_vdev_device *dev)
{
	int rc;
	const char * params=rte_vdev_device_args(dev);
	const char * dev_name=rte_vdev_device_name(dev);
	char underlay_dev_params[128];
	uint32_t remote_ip=0; /*all in big endian*/
	uint32_t local_ip=0;
	struct rte_kvargs * kvlist=NULL;
	uint8_t underlay_port=-1;
	memset(underlay_dev_params,0x0,sizeof(underlay_dev_params));
	
	kvlist=rte_kvargs_parse(params,valid_arguments);
	if(!kvlist)
		return -1;
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
	rte_kvargs_free(kvlist);
	if(!underlay_dev_params[0]||!remote_ip||!local_ip){
		printf("[VXLAN PMD]INVALID ARGUMENTS FOR VXLAN PMD\n");
		return -2;
	}
	/*1 register the underlay dev*/
	rc=rte_eth_dev_attach(underlay_dev_params,&underlay_port);
	if(rc){
		printf("[VXLAN PMD]CAN NOT ATTACH PORT WITH ARG:%s\n",underlay_dev_params);
		return -3;
	}
	printf("[VXLAN PMD]:ATTACH %s AS PORT %d\n",underlay_dev_params,underlay_port);
	
	return 0;

	error_dev_detach:
		
		return 0;
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
	VXLAN_PMD_ARG_REMOTE_IP "=<ip-addr> ");

