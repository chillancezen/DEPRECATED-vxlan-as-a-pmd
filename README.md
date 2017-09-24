##### what's it?

This DPDK pmd extension power you with the ability to make a physical nic a dedicated E-LINE service  like virtual link.
one vxlan pmd relies on a physical link with (IP csum calculation /VLAN stripping and insertion) offload capability, and one physical device serves only one virtual vxlan pmd, yet we name it `vxlan as a pmd` since we use SR-IOV as the virtualization base for multi-tenancy application,with which we predefine enough virtual function and make it a virtul overlay pmd.


##### how to setup virtual vxlan pmd vdev?

here we present the vdev parameter sample :
```c
--vdev=eth_vxlan0,\
underlay_dev="0000:00:08.0",\
remote_ip='2.2.2.2',\
local_ip='2.2.2.1',\
vni=1000,\
underlay_vlan=100

```

 - `underlay_dev` is the pci address of the underlay nic, usually a virtual function address
 - `remote_ip` is the address of remote endpoint in the underlay network
 - `local_ip` is the address of local endpoint 
 - `vni` is the vxlan identifier
 - `vlan` is the vlan id the underlay network use, this is optional
 
when setting up the vxlan pmd vdev, it registers the pci device as corresponding underlay, DO NOT manipulate the `nested underlay port` since it's taken over by vxlan overlay vdev.


##### vxlan pmd performance.

with pktgen :
```bash
./app/x86_64-native-linuxapp-gcc/pktgen -w 0000:00:00.0  --vdev=eth_vxlan0,underlay_dev="0000:00:08.0",remote_ip='2.2.2.2',local_ip='2.2.2.1',vni=1000,underlay_vlan=100 -- -P -T -f themes/white-black.theme -m '[1:2].1'
```

```bash

/ Ports 0-1 of 2   <Main Page>  Copyright (c) <2010-2017>, Intel Corporation
  Flags:Port      :                       P--------------:1
Link State        :                           <UP-10000-FD>--
Pkts/s Max/Rx     :                                       3/0
       Max/Tx     :                             205442/158320
MBits/s Rx/Tx     :                                   0/16802
Broadcast         :                                       0
Multicast         :                                       0
  64 Bytes        :                                       0
  65-127          :                                       0
  128-255         :                                       0
  256-511         :                                       0
  512-1023        :                                       0
  1024-1518       :                                       0
Runts/Jumbos      :                                     0/0
Errors Rx/Tx      :                                     0/0
Total Rx Pkts     :                                      24
      Tx Pkts     :                                 2968220
      Rx MBs      :                                       0
      Tx MBs      :                                  194323
ARP/ICMP Pkts     :                                     0/0
                  :
Pattern Type      :                                 abcd...
Tx Count/% Rate   :                           Forever /100%
PktSize/Tx Burst  :                               64 /   64
Src/Dest Port     :                             1234 / 5678
Pkt Type:VLAN ID  :                         IPv4 / TCP:0001
Dst  IP Address   :                             192.168.0.1
Src  IP Address   :                          192.168.1.1/24
Dst MAC Address   :                       00:00:00:00:00:00
Src MAC Address   :                       08:00:28:1c:d8:fa
VendID/PCI Addr   :                       0000:0000/00:00.0

-- Pktgen Ver: 3.4.2 (DPDK 17.08.0)  Powered by DPDK --------------------------
```

and the utimate performance may need more work on it
