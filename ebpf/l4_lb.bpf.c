#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
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
#include "l4_lb_utils.h"

typedef struct {
    __be32 destination;
    __be16 total_length;
    __u8 protocol;
} ip_parse_ret;

struct bpf_iter_num {
    int start;
    int end;
    int current;
};


static __always_inline int parse_iphdr(void *data, void *data_end, __u16 *nh_off, struct iphdr **iphdr, ip_parse_ret *result) {
    struct iphdr *ip = data + *nh_off;
    int hdr_size;

    if ((void *)ip + sizeof(*ip) > data_end)
        return -1;
    
    hdr_size = ip->ihl * 4;
    
    if(hdr_size < sizeof(*ip))
        return -1;

    if ((void *)ip + hdr_size > data_end)
        return -1;

    *nh_off += hdr_size;
    *iphdr = ip;

    result->destination = ip->addrs.daddr;
    result->total_length = ip->tot_len;
    result->protocol = ip->protocol;

   return 0;
}

static __always_inline int parse_ethhdr(void *data, void *data_end, __u16 *nh_off, struct ethhdr **ethhdr) {
   struct ethhdr *eth = (struct ethhdr *)data;
   int hdr_size = sizeof(*eth);

   if ((void *)eth + hdr_size > data_end)
      return -1;

   *nh_off += hdr_size;
   *ethhdr = eth;

    /* MAC dest address on arrival */

    bpf_printk("[DEBUG]: MAC dest on the input packet %02x:%02x:%02x:%02x:%02x:%02x", eth->h_dest[0], eth->h_dest[1], 
    eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

    /* MAC source address on arrival */

    bpf_printk("[DEBUG]: MAC soruce on the input packet %02x:%02x:%02x:%02x:%02x:%02x", eth->h_source[0], 
    eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);

   return eth->h_proto; 
}

static __always_inline int parse_udphdr(void *data, void *data_end, __u16 *nh_off, struct udphdr **udphdr)
{
    struct udphdr *udp = data + *nh_off; 

    if ((void *)udp + sizeof(udp) > data_end){
        return -1; 
    }

    *nh_off += sizeof(*udp);
    *udphdr = udp; 

    return 0; 

}

static __always_inline int is_flow_present(four_tuple input_tuple){
    chosen_backend *tmp; 
    tmp = bpf_map_lookup_elem(&flow_map, &input_tuple);
    if (!tmp){
        bpf_printk("[DEBUG]: flow not present, check the state of the backends\n");
        return 0;
    }
    else {   
        bpf_printk("[DEBUG]: flow already present");
        return 1; 
    }
}

static __always_inline int backend_search(){

    int min = 10000; 
    int ind = 0;
    int *n_backends = bpf_map_lookup_elem(&number_of_backends, &ind);
    if (!n_backends){
        return -1; 
    }
     
    backend_info *res;
    int i;  
    bpf_for(i,0,*n_backends){
        res = bpf_map_lookup_elem(&flow_packets_count_map, &i);
        
        if (!res){
            bpf_printk("[ERROR]: map lookup (flow_packets_count_map) went wrong"); 
            return -1; 
        }
        bpf_printk("[DEBUG]: Backend %d | Number of flows %d | Number of packets %d | Load  %d |",res ->backend_ip, res->flows_count, res->pkts_count, res->load);

        if (res->load<min){
            min = res->load; 
            ind = i; 
        }
    }
    return ind; 
}

static __always_inline __u16 ip_checksum(struct iphdr *iphdr) {
    __u32 sum = 0;
    __u16 *ptr = (__u16 *)iphdr;

    #pragma clang loop unroll(full)
    for (int i = 0; i < sizeof(*iphdr) >> 1; i++) {
        sum += *ptr++;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (__u16)(~sum);
}


SEC("xdp")
int l4_lb(struct xdp_md *ctx) {

    int key = 0; 
    __u16 nf_off = 0;
    struct ethhdr *eth;
    int eth_type;
    struct iphdr *ip;
    int err_ip;
    ip_parse_ret ip_result;
    struct udphdr *udp; 
    int err_udp;
    __u32  *vip;
    four_tuple input_tuple; 
    int index; 
    backend_info *back; 
    int ret; 
    chosen_backend final;
    int enlargement;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Setting vip */

    vip = bpf_map_lookup_elem(&vip_map, &key);
    if (vip == NULL){
        bpf_printk("[ERROR]: no vip in config.yaml");
        goto drop; 
    }

    bpf_printk("________________________________________________________________\n");
    bpf_printk("[DEBUG]: New packet received\n");

    /* ****************** PARSING ****************** */

    bpf_printk("****************** START PARSING ******************\n");

    eth_type = parse_ethhdr(data, data_end, &nf_off, &eth);

    /* [ETHERNET PARSING] Check if it's an ARP packet, if so let it pass */
    if (eth_type == bpf_ntohs(ETH_P_ARP)) {
        bpf_printk("[DEBUG]: ARP request");
        bpf_printk("[DEBUG]: packet succesfully parsed\n");
        bpf_printk("****************** END PARSING ******************\n");
        goto pass;
    }

    // [ETHERNET PARSING] Check if it's an IP packet otherwise drop the packet
    if (eth_type != bpf_ntohs(ETH_P_IP)) {
        bpf_printk("[DEBUG]: etherType is not IP so DROP the packet");
        goto drop;
    }
    bpf_printk("[DEBUG]: etherType is IP");

    err_ip = parse_iphdr(data, data_end, &nf_off, &ip, &ip_result);
        
    if (err_ip != 0){
        bpf_printk("[ERROR]: parsing of the IP header failed so DROP the packet");
        goto drop;
    }

    // [IP PARSING] Check if it's an UDP packet otherwise drop the packet
    if (ip_result.protocol != IPPROTO_UDP) {
        bpf_printk("[DEBUG]: protocol is not UDP so DROP the packet");
        goto drop;
    }
    bpf_printk("[DEBUG]: protocol is UDP");
    
    // [IP PARSING]: Check if the IP destination is the vip otherwise drop the packet
    if (bpf_ntohl(ip_result.destination) != *vip){
        bpf_printk("[DEBUG]: IP dest is not the vip so DROP the packet");
        goto drop;
    }

    err_udp = parse_udphdr(data, data_end, &nf_off, &udp);
    if (err_udp != 0)
    {
        bpf_printk("[DEBUG]: parsing of the UDP header failed so DROP the packet");
        goto drop; 
    }
    
    bpf_printk("[DEBUG]: packet succesfully parsed\n");
    bpf_printk("****************** END PARSING ******************\n");
    
    /* ****************** PARSING ****************** */

    /* ****************** FLOW CHECK ****************** */

    bpf_printk("****************** START FLOW CHECKS ******************\n");
    
    /* Retrieve the tuple used to check if the flow is already present in the map */
    input_tuple.dst_ip = bpf_ntohl(ip->addrs.daddr);
    input_tuple.src_ip = bpf_ntohl(ip->addrs.saddr);
    input_tuple.src_port = bpf_ntohs(udp->source);
    input_tuple.dst_port = bpf_ntohs(udp->dest);  

    if (is_flow_present(input_tuple) == 0){

        // Flow not present in the map, pick a new server and assign the flow to it
        index = backend_search(); 
        bpf_printk("[DEBUG]: new backend selected of index %d\n", index); 
        
        back = bpf_map_lookup_elem(&flow_packets_count_map, &index); 
        if (!back)
        {  
            bpf_printk("[ERROR]: map lookup (flow_packets_count_map) went wrong");
            goto drop; 
        }

        // Update the state of the backend
        back->flows_count++; 
        back->pkts_count++;
        back->load = back->pkts_count / back->flows_count; 

        // Update the flow_packets_count_map
        ret = bpf_map_update_elem(&flow_packets_count_map, &index, back, BPF_ANY);
        // bpf_printk("[DEBUG] bpf_map_update_elem return value: %d", ret);
        if (ret < 0) {
            bpf_printk("[ERROR]: map update (flow_packets_count_map) went wrong\n");
            goto drop;
        }

        final.backend_ip = back->backend_ip;
        final.index = index;

        // Update the flow map, adding the new flow to the associated server
        ret = bpf_map_update_elem(&flow_map, &input_tuple, &final, BPF_ANY);
        if (ret < 0){
            bpf_printk("[ERROR]: map update (flow_map) went wrong"); 
            goto drop; 
        }

        
    }
    else{
        // Flow already present in the map
        chosen_backend * selected_backend = bpf_map_lookup_elem(&flow_map, &input_tuple); 
        if (!selected_backend){
            goto drop; 
        }
        bpf_printk("[DEBUG]: flow associated to server with index %d\n", selected_backend->index); 
        back = bpf_map_lookup_elem(&flow_packets_count_map, &selected_backend->index); 
        if (!back)
        {  
            bpf_printk("[ERROR]: map lookup (flow_packets_count_map) went wrong"); 
            goto drop; 
        }
        back->pkts_count++;
        back->load = back->pkts_count / back->flows_count; 
        final.backend_ip = selected_backend->backend_ip;
    }
    

    bpf_printk("[DEBUG]: Backend %d updated | Number of flows %d | Number of packets %d | Load  %d |\n", back->backend_ip, back->flows_count, back->pkts_count, back->load);
    bpf_printk("****************** END FLOW CHECKS ******************\n");

    /* ****************** FLOW CHECK ****************** */

    /* ****************** PACKET UPDATE ****************** */

    bpf_printk("****************** START PACKET UPDATE ******************\n");

    unsigned char tmp_mac[ETH_ALEN]; // pivot variable to swap two arrays (MAC addresses bytes)
  
    #pragma unroll 
    for (int i = 0; i< ETH_ALEN; i++){
        /* this for loop swaps MAC dest and MAC source addresses*/
        tmp_mac[i] = eth->h_dest[i];
        eth->h_dest[i] = eth->h_source[i];
        eth->h_source[i] = tmp_mac[i];
    }

    int pkt_length = ip->tot_len; 
    enlargement = sizeof(struct iphdr);
    bpf_printk("[DEBUG]: packet length in host format before enlarging %d", bpf_ntohs(pkt_length));
    if (bpf_xdp_adjust_head(ctx, 0-enlargement)){   // we make it negative in order to enlarge the packet
        bpf_printk("[ERROR]: packet enlarging went wrong"); 
        goto drop; 
    }
    
    // We must set the pointers we decleared in the code to the context of the XDP program, now changed after the enlargement
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    if (data + sizeof(*eth) + enlargement + sizeof(*ip) + sizeof(*udp) > data_end) {
        bpf_printk("[ERROR]: enlarging of the packet failed so DROP the packet");
        goto drop;
    }

    /* We just moved the pointers after the enlargement, now we actually move the data (only the ethernet header actually) */
    struct ethhdr *eth2 = data;
    __builtin_memcpy(eth2, data + enlargement, sizeof(struct ethhdr));

    /* outgoing MAC dest address */

    bpf_printk("[DEBUG]: MAC dest on the output packet %02x:%02x:%02x:%02x:%02x:%02x", eth2->h_dest[0], 
    eth2->h_dest[1], eth2->h_dest[2], eth2->h_dest[3], eth2->h_dest[4], eth2->h_dest[5]);

    /* outgoing MAC source address */

    bpf_printk("[DEBUG]: MAC source on the output packet %02x:%02x:%02x:%02x:%02x:%02x", eth2->h_source[0], 
    eth2->h_source[1], eth2->h_source[2], eth2->h_source[3], eth2->h_source[4], eth2->h_source[5]);
    
    /* forge the new IP header that will contain the old IP header */

    struct iphdr *ip2 = data + sizeof(struct ethhdr);
    ip2->version = 4; 
    ip2->ihl = 5; 
    ip2->tos = 0; 
    ip2->tot_len = bpf_htons(bpf_ntohs(pkt_length) + enlargement);  
    ip2->id = bpf_htons(1); 
    ip2->frag_off = 0; 
    ip2->ttl = 64; 
    ip2->protocol = IPPROTO_IPIP; 
    ip2->check = 0; 
    ip2->addrs.saddr = bpf_htonl(input_tuple.src_ip); 
    ip2->addrs.daddr = final.backend_ip; 

    /* Checksum calculation */

    ip2->check = ip_checksum(ip2);

    bpf_printk("[DEBUG]: packet length in host format after enlarging %d\n", bpf_ntohs(ip2->tot_len));
    bpf_printk("****************** END PACKET UPDATE ******************\n");

    /* ****************** PACKET UPDATE ****************** */

    /* ****************** PRINT THE NEW IP ****************** */

    bpf_printk("------------------ NEW IP HEADER ------------------");

    bpf_printk("IP source %u", ip2->addrs.saddr);
    bpf_printk("IP dest %u (in host format %u)", ip2->addrs.daddr, bpf_ntohl(ip2->addrs.daddr));
    bpf_printk("IP ttl %u", ip2->ttl);
    bpf_printk("IP protocol %u", ip2->protocol);
    bpf_printk("IP id %u\n", ip2->id);

    /* ****************** PRINT THE NEW IP ****************** */

    goto end; 


pass:
    bpf_printk("[DEBUG - SUCCESS]: packet passed"); 
    return XDP_PASS;
drop:
    bpf_printk("[DEBUG]: packet dropped");
    return XDP_DROP;
end: 
    bpf_printk("[DEBUG - SUCCESS]: packet retransmitted"); 
    return XDP_TX;
    /* Using XDP_TX I can't see packets returning on neither of the two virtual interfaces sniffing on them I don't 
    know why. Using XDP_PASS one can see the packet is correctly processed by sniffing on veth1_ using wireshark */
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
