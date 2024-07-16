#ifndef L4_LB_UTILS_H_
#define L4_LB_UTILS_H_

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stddef.h>
#include <stdint.h>

    typedef struct{
		__uint32_t backend_ip; 
		__uint16_t flows_count;
		__uint16_t pkts_count;
		__uint16_t load; 
	} backend_info;
	
	typedef struct{
		__uint32_t src_ip;
		__uint32_t dst_ip;
		__uint16_t src_port;
		__uint16_t dst_port;
	} four_tuple;

	typedef struct{
		__uint32_t backend_ip;
		__uint16_t index;
	} chosen_backend;

	// This map stores the VIP that identifies the load balancer (it is the destination of the input packet)
	struct{
		__uint(type, BPF_MAP_TYPE_ARRAY); 
		__type(key, int); 
		__type(value, __u32); 
		__uint(max_entries, 1); 
	} vip_map SEC(".maps");     

	// This map stores the number of backens used to iterate in the bpf program anc search for the one with the lowest load
	struct{
		__uint(type, BPF_MAP_TYPE_ARRAY);
		__type(key, int); 
		__type(value, __u32);
		__uint(max_entries, 1);
	} number_of_backends SEC(".maps");

 	// This map stores the association with flows (the four_tuple) and backends server where they are sent to be processed
	struct {
		__uint(type, BPF_MAP_TYPE_HASH);
		__type(key, four_tuple );
		__type(value, chosen_backend);
		__uint(max_entries, 10000);
	} flow_map SEC(".maps");
	
	// This map stores for each backend server its information like ip, packets received, how many flows it handles and load 
	struct {
		__uint(type, BPF_MAP_TYPE_ARRAY);
		__type(key, __u32);
		__type(value, backend_info);
		__uint(max_entries, 100);
	} flow_packets_count_map SEC(".maps");


#endif // L4_LB_UTILS_H_
